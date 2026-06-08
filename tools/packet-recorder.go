package main

import (
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"time"
)

// ProxyServer adalah TCP proxy yang merekam semua packet antara client dan server.
type ProxyServer struct {
	listenAddr string
	targetAddr string
	logFile    *os.File
}

// NewProxyServer membuat proxy baru.
func NewProxyServer(listenAddr, targetAddr, logPath string) (*ProxyServer, error) {
	logFile, err := os.Create(logPath)
	if err != nil {
		return nil, err
	}

	return &ProxyServer{
		listenAddr: listenAddr,
		targetAddr: targetAddr,
		logFile:    logFile,
	}, nil
}

// Start memulai proxy server.
func (p *ProxyServer) Start() error {
	listener, err := net.Listen("tcp", p.listenAddr)
	if err != nil {
		return err
	}
	defer listener.Close()

	log.Printf("Proxy listening on %s, forwarding to %s", p.listenAddr, p.targetAddr)
	log.Printf("Logging to: %s", p.logFile.Name())

	for {
		clientConn, err := listener.Accept()
		if err != nil {
			log.Printf("Accept error: %v", err)
			continue
		}

		go p.handleConnection(clientConn)
	}
}

// handleConnection menangani satu client connection.
func (p *ProxyServer) handleConnection(clientConn net.Conn) {
	defer clientConn.Close()

	// Connect ke target server
	serverConn, err := net.Dial("tcp", p.targetAddr)
	if err != nil {
		log.Printf("Failed to connect to target %s: %v", p.targetAddr, err)
		return
	}
	defer serverConn.Close()

	sessionID := fmt.Sprintf("%d", time.Now().Unix())
	p.logEvent(sessionID, "SESSION_START", fmt.Sprintf("Client: %s -> Proxy: %s -> Server: %s",
		clientConn.RemoteAddr(), p.listenAddr, p.targetAddr))

	// Bidirectional forwarding
	done := make(chan bool, 2)

	// Client -> Server
	go func() {
		p.forward(sessionID, "C->S", clientConn, serverConn)
		done <- true
	}()

	// Server -> Client
	go func() {
		p.forward(sessionID, "S->C", serverConn, clientConn)
		done <- true
	}()

	// Wait for both directions to finish
	<-done
	<-done

	p.logEvent(sessionID, "SESSION_END", "Connection closed")
}

// forward mem-forward data dari src ke dst dan log semua bytes.
func (p *ProxyServer) forward(sessionID, direction string, src, dst net.Conn) {
	buf := make([]byte, 4096)
	packetNum := 0

	for {
		n, err := src.Read(buf)
		if err != nil {
			if err != io.EOF {
				p.logEvent(sessionID, direction, fmt.Sprintf("Read error: %v", err))
			}
			return
		}

		if n > 0 {
			packetNum++
			data := buf[:n]

			// Log packet
			timestamp := time.Now().Format("15:04:05.000")
			hexDump := hex.Dump(data)
			p.logPacket(sessionID, direction, packetNum, timestamp, n, hexDump)

			// Forward to destination
			if _, err := dst.Write(data); err != nil {
				p.logEvent(sessionID, direction, fmt.Sprintf("Write error: %v", err))
				return
			}
		}
	}
}

// logPacket mencatat packet ke file.
func (p *ProxyServer) logPacket(sessionID, direction string, num int, timestamp string, size int, hexDump string) {
	entry := fmt.Sprintf("\n=== [%s] %s Packet #%d @ %s (%d bytes) ===\n%s\n",
		sessionID, direction, num, timestamp, size, hexDump)

	p.logFile.WriteString(entry)
	p.logFile.Sync()

	// Also print to console (shorter version)
	fmt.Printf("[%s] %s #%d: %d bytes @ %s\n", sessionID, direction, num, size, timestamp)
}

// logEvent mencatat event ke file.
func (p *ProxyServer) logEvent(sessionID, eventType, message string) {
	timestamp := time.Now().Format("15:04:05.000")
	entry := fmt.Sprintf("\n=== [%s] %s @ %s ===\n%s\n", sessionID, eventType, timestamp, message)

	p.logFile.WriteString(entry)
	p.logFile.Sync()

	fmt.Printf("[%s] %s: %s\n", sessionID, eventType, message)
}

func main() {
	if len(os.Args) < 4 {
		fmt.Println("Usage: packet-recorder <listen_port> <target_host:port> <log_file>")
		fmt.Println("Example: packet-recorder 12022 127.0.0.1:12022 validation.log")
		os.Exit(1)
	}

	listenAddr := "0.0.0.0:" + os.Args[1]
	targetAddr := os.Args[2]
	logPath := os.Args[3]

	proxy, err := NewProxyServer(listenAddr, targetAddr, logPath)
	if err != nil {
		log.Fatalf("Failed to create proxy: %v", err)
	}

	if err := proxy.Start(); err != nil {
		log.Fatalf("Proxy error: %v", err)
	}
}
