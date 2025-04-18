package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"math/rand"
	"time"
	"strings"
)


func main() {
	// Request user input for message to send
	reader := bufio.NewReader(os.Stdin)
	rand.Seed(time.Now().UnixNano())
	for {
		fmt.Printf("Enter plaintext to authenticate: ")
		text, err := reader.ReadString('\n')
		if err != nil {
			fmt.Println("Input error:", err)
			continue
		}
		text = strings.TrimSpace(text)
		if text == "" {
			fmt.Println("Please type something non‐empty.")
			continue
		}

		//call to authenticate
		ok, err := authenticateWithKDC(text)
		if err != nil {
			fmt.Println("Authentication error:", err)
			continue
		}

		if ok {
			fmt.Println("✅ Authentication succeeded!")
			//user approved to proceed
			break
		} else {
			fmt.Println("❌ Authentication failed.")
			// forces user to retry
		}
	}
	
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