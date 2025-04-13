package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
)


func main() {
	startServer()
}


func startServer() {
	// Server (listening on a port)
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

	reader := bufio.NewReader(conn)
	
	message, err := reader.ReadString('\n') // Read until newline
	if err != nil {
		fmt.Println("Error reading from connection:", err)
		return
	}
	fmt.Printf("Received from Client: %s", message) // print message received




	buf := []byte("Hello client\n")

	conn.Write(buf)

	return
} 