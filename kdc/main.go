package main

import (
	"bufio"
	crypto_rand "crypto/rand"
	"crypto/sha256"
	"encoding/gob"
	"fmt"
	"math/big"
	math_rand "math/rand"
	"net"
	"os"
	"time"
)

var authenticated bool = false

// Same p and g (must match client)
var (
	pHex = "some hex"
	g    = big.NewInt(2)
)

func main() {
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
	sessionKey := sha256.Sum256(sharedSecret.Bytes())
	fmt.Printf("Shared secret (session key) calculated: %x\n", sessionKey)

	// reading client's message
	reader := bufio.NewReader(conn)

	message, err := reader.ReadString('\n') // Read until newline
	if err != nil {
		fmt.Println("Error reading from connection:", err)
		return
	}
	fmt.Printf("Received from Client: %s", message) // print message received

	// 50/50 approval
	if !authenticated {
		if math_rand.Intn(2) == 0 {
			conn.Write([]byte("OK\n"))
			authenticated = true
		} else {
			conn.Write([]byte("FAIL\n"))
		}
	}

	buf := []byte("Hello client\n")

	conn.Write(buf)

	return
}
