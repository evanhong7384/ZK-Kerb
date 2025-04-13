package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
)


func main() {
	// Request user input for message to send
	reader := bufio.NewReader(os.Stdin)
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