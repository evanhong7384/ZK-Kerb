package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
)


func main() {
	go startServer()

	// Request user input for message to send
	reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Printf("Send message to Server2: ")
		msg, err := reader.ReadString('\n') // Read the entire line, including spaces
        if err != nil {
            fmt.Println("Error reading input:", err)
            continue
        }

        // Remove the newline character from the input
        msg = msg[:len(msg)-1]
		
		go startClient(&msg)
	}
}


func startServer() {
	// Server (listening on a port)
	listener, err := net.Listen("tcp", ":8081") // 8081 for server1, 8082 for server2
	if err != nil {
	// Handle error
	}
	defer listener.Close()

	for {
	conn, err := listener.Accept()
	if err != nil {
		// Handle error
		continue
	}
	go handleConnection(conn) // Handle each connection in a goroutine

	}
}


func handleConnection(conn net.Conn) {
	defer conn.Close()

	reader := bufio.NewReader(conn)
	
	for {
        message, err := reader.ReadString('\n') // Read until newline
        if err != nil {
            fmt.Println("Error reading from connection:", err)
            return
        }
        fmt.Printf("\n -------\n")
        fmt.Printf("Received from Server2: %s", message) // print message received
		fmt.Printf(" -------\n")
		fmt.Printf("Send message to Server2: ") 
		return
    }
}

func startClient(msg *string) {
	// Client (connecting to the server)
	conn, err := net.Dial("tcp", ":8082") // 8081 for server1, 8082 for server2
	defer conn.Close()
	if err != nil {
	// Handle error
		return
	}

	_, err = conn.Write([]byte(*msg + "\n"))
	if err != nil {
		fmt.Println("Error writing to connection:", err)
		return
	}
}
