package main

import (
	"bytes"
	"context"
	crypto_rand "crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/gob"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	math_rand "math/rand"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

type Circuit struct {
	X frontend.Variable `gnark:"x"`       // x  --> secret visibility (default)
	Y frontend.Variable `gnark:",public"` // Y  --> public visibility
}

func (c *Circuit) Define(api frontend.API) error {
	// binary multiply twice instead of one 3-way Mul
	x2 := api.Mul(c.X, c.X)
	x3 := api.Mul(x2, c.X)

	// binary add twice instead of one 3-way Add
	sum1 := api.Add(x3, c.X)
	res := api.Add(sum1, 5)

	api.AssertIsEqual(res, c.Y)
	return nil
}

var verifyingKey groth16.VerifyingKey
var provingKey groth16.ProvingKey
var authenticated bool = false

// Same p and g (must match client)
var (
	pHex = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" +
		"29024E088A67CC74020BBEA63B139B22514A08798E3404DD" +
		"EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" +
		"E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" +
		"EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D" +
		"C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F" +
		"83655D23DCA3AD961C62F356208552BB9ED529077096966D" +
		"670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF"
	g = big.NewInt(2)
)

func main() {
	ZKKDC()
	startServer()
}

func startServer() {
	// Server (listening on a port)
	math_rand.Seed(time.Now().UnixNano())
	listener, err := net.Listen("tcp", ":8080")
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	defer listener.Close()

	for {
		conn, err := listener.Accept()
		if err != nil {
			fmt.Println("Error accepting connection: ", err)
			continue
		}

		go handleConnection(conn) // Handle each connection in a goroutine

	}
}

func handleConnection(conn net.Conn) {
	defer conn.Close()

	// key exchange
	var clientPub big.Int
	decoder := gob.NewDecoder(conn)
	err := decoder.Decode(&clientPub)
	if err != nil {
		fmt.Println("Error receiving client public key:", err)
		return
	}

	p, _ := new(big.Int).SetString(pHex, 16)
	kdcPrivate, _ := crypto_rand.Int(crypto_rand.Reader, p)
	kdcPublic := new(big.Int).Exp(g, kdcPrivate, p)

	encoder := gob.NewEncoder(conn)
	err = encoder.Encode(kdcPublic)
	if err != nil {
		fmt.Println("Error sending KDC public key:", err)
		return
	}

	sharedSecret := new(big.Int).Exp(&clientPub, kdcPrivate, p)
	mock_password := sha256.Sum256(sharedSecret.Bytes())
	fmt.Printf("Shared secret (session key) calculated: %x\n", mock_password)

	return
}

func ZKKDC() {

	proofOK := make(chan struct{})
	mux := http.NewServeMux()

	// ——— compile + trusted setup ———
	var circuit Circuit
	cs, err := frontend.Compile(
		ecc.BN254.ScalarField(),
		r1cs.NewBuilder,
		&circuit,
	)
	if err != nil {
		log.Fatalf("compile error: %v", err)
	}
	pk, vk, err := groth16.Setup(cs)
	if err != nil {
		log.Fatalf("setup error: %v", err)
	}
	provingKey = pk
	verifyingKey = vk
	log.Printf("🔑 Setup complete; server listening on :8081")

	// 2) expose proving key
	http.HandleFunc("/pk", func(w http.ResponseWriter, r *http.Request) {
		var buf bytes.Buffer
		if _, err := provingKey.WriteTo(&buf); err != nil {
			http.Error(w, "failed to serialize PK", http.StatusInternalServerError)
			return
		}
		pkB64 := base64.StdEncoding.EncodeToString(buf.Bytes())
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"pk": pkB64})
	})

	// ——— expose verifying key ———
	http.HandleFunc("/vk", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(verifyingKey)
	})

	// ——— proof‐verification endpoint ———
	http.HandleFunc("/prove", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ProofB64 string `json:"proof"`
			Y        int    `json:"y"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}

		// 2) Base64 → []byte
		proofBytes, err := base64.StdEncoding.DecodeString(req.ProofB64)
		if err != nil {
			http.Error(w, "invalid proof encoding", http.StatusBadRequest)
			return
		}

		// 3) Allocate an empty Proof of the right curve type
		proof := groth16.NewProof(ecc.BN254)

		buf := bytes.NewBuffer(proofBytes)
		if _, err := proof.ReadFrom(buf); err != nil {
			http.Error(w, "invalid proof format", http.StatusBadRequest)
			return
		}
		// build a public witness with just Y
		assignment := Circuit{Y: req.Y}
		pubWit, err := frontend.NewWitness(
			&assignment,
			ecc.BN254.ScalarField(),
			frontend.PublicOnly(),
		)
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		// verify
		if err := groth16.Verify(proof, verifyingKey, pubWit); err != nil {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		select {
		case <-proofOK:
		default:
			close(proofOK)
		}
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "OK")

	})

	srv := &http.Server{
		Addr:    ":8081",
		Handler: mux,
	}

	go func() {
		log.Fatal(http.ListenAndServe(":8081", nil))
	}()
	<-proofOK

	// 6) gracefully shut down the HTTP server
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		log.Fatalf("HTTP shutdown error: %v", err)
	}

}
