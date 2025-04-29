package main

import (
	"bufio"
	crypto_rand "crypto/rand"
	"crypto/sha256"
	"encoding/gob"
	"fmt"
	"math/big"
	"net"
	"os"
	"time"
	"strings"
	"bytes"
	"encoding/json"
	"encoding/base64"
	"io/ioutil"
	"log"
	"net/http"

	"github.com/consensys/gnark/backend/groth16"
    "github.com/consensys/gnark/frontend"
    "github.com/consensys/gnark/frontend/cs/r1cs"
    "github.com/consensys/gnark-crypto/ecc"
)

// Circuit must match the server’s
type Circuit struct {
    X frontend.Variable `gnark:"x"`
    Y frontend.Variable `gnark:",public"`
}

func (c *Circuit) Define(api frontend.API) error {
    x2  := api.Mul(c.X, c.X)
    x3  := api.Mul(x2, c.X)
    sum := api.Add(x3, c.X)
    res := api.Add(sum, 5)
    api.AssertIsEqual(res, c.Y)
    return nil
}

// Same p and g (must match KDC)
var (
	pHex = "some hex"
	g    = big.NewInt(2)
)

func main() {
	// Request user input for message to send
	reader := bufio.NewReader(os.Stdin)
		
	
	ZKAuth()
	
	fmt.Println("✅ Authenticated — now starting client session.")

	for {
		fmt.Printf("Send message to KDC: ")
		msg, err := reader.ReadString('\n') // Read the entire line, including spaces
		if err != nil {
			fmt.Println("Error reading input:", err)
			continue
		}

		// Remove the newline character from the input
		msg = msg[:len(msg)-1]

		startClient(&msg)
	}
}

func startClient(msg *string) {
	// Client (connecting to the server)
	conn, err := net.Dial("tcp", ":8080") 
	defer conn.Close()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	// key exchange
	p, _ := new(big.Int).SetString(pHex, 16)
	userPriv, _ := crypto_rand.Int(crypto_rand.Reader, p)
	userPub := new(big.Int).Exp(g, userPriv, p)

	encoder := gob.NewEncoder(conn)
	err = encoder.Encode(userPub)
	if err != nil {
		fmt.Println("Error sending user public key:", err)
		os.Exit(1)
	}

	var kdcPub big.Int
	decoder := gob.NewDecoder(conn)
	err = decoder.Decode(&kdcPub)
	if err != nil {
		fmt.Println("Error receiving KDC public key:", err)
		os.Exit(1)
	}

	sharedSecret := new(big.Int).Exp(&kdcPub, userPriv, p)
	sessionKey := sha256.Sum256(sharedSecret.Bytes())
	fmt.Printf("Derived session key: %x\n", sessionKey)

	// authentication
	_, err = conn.Write([]byte(*msg + "\n"))
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	buf := make([]byte, 1024)

	n, err := conn.Read(buf)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	fmt.Printf("Received: %s\n", buf[:n])
}

func authenticateWithKDC(plaintext string) (bool, error) {
	// contacts kdc
	conn, err := net.DialTimeout("tcp", "localhost:8080", 5*time.Second)
	if err != nil {
		return false, fmt.Errorf("cannot connect to KDC: %w", err)
	}
	defer conn.Close()

	// ships plaintext
	_, err = fmt.Fprintf(conn, "%s\n", plaintext)
	if err != nil {
		return false, fmt.Errorf("failed to send auth request: %w", err)
	}

	// look at authentication response
	resp, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		return false, fmt.Errorf("failed to read KDC response: %w", err)
	}

	// Trim whitespace and check for “OK”
	resp = strings.TrimSpace(resp)
	if resp == "OK" {
		return true, nil
	}
	return false, nil
}

func ZKAuth() {
	// 1) compile the circuit (same code as server)
    var circuit Circuit
    cs, err := frontend.Compile(
        ecc.BN254.ScalarField(),
        r1cs.NewBuilder,
        &circuit,
    )
    if err != nil {
        log.Fatalf("compile circuit: %v", err)
    }

    // ─────── STEP 2: FETCH PK FROM SERVER ───────
    resp, err := http.Get("http://localhost:8081/pk")
    if err != nil {
        log.Fatalf("GET /pk error: %v", err)
    }
    defer resp.Body.Close()
    var got struct{ PK string `json:"pk"` }
    if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
        log.Fatalf("decode /pk response: %v", err)
    }
    // Base64 → raw bytes
    rawPK, err := base64.StdEncoding.DecodeString(got.PK)
    if err != nil {
        log.Fatalf("invalid base64 PK: %v", err)
    }
    // fill a new ProvingKey
    pk := groth16.NewProvingKey(ecc.BN254)
    if _, err := pk.ReadFrom(bytes.NewReader(rawPK)); err != nil {
        log.Fatalf("unmarshal PK: %v", err)
    }

    // 3) build a witness for x=3
    x := 3
    y := x*x*x + x + 5
    assignment := Circuit{X: x, Y: y}
    fullWit, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
    if err != nil {
        log.Fatalf("new witness: %v", err)
    }

    // 4) generate proof
    proof, err := groth16.Prove(cs, pk, fullWit)
    if err != nil {
        log.Fatalf("prove: %v", err)
    }

	// ─── serialize proof ──────────────────────────────────────────
// use WriteTo to dump the proof into a bytes.Buffer
	buf := new(bytes.Buffer)
	if _, err := proof.WriteTo(buf); err != nil {
		log.Fatalf("proof.WriteTo: %v", err)
	}
	proofBytes := buf.Bytes()

	// 2) Base64-encode for JSON transport
	proofB64 := base64.StdEncoding.EncodeToString(proofBytes)

    // 5) send proof + public Y to server
    payload := map[string]interface{}{
        "proof": proofB64,
        "y":     y,
    }
    b, _ := json.Marshal(payload)
    resp2, err := http.Post("http://localhost:8081/prove", "application/json", bytes.NewReader(b))
    if err != nil {
        log.Fatalf("POST error: %v", err)
    }
    defer resp2.Body.Close()
	respBody, _ := ioutil.ReadAll(resp2.Body)
	fmt.Printf("Server responded [%d]: %s\n", resp2.StatusCode, string(respBody))
}