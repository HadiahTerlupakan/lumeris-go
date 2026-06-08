package main
import (
	"fmt"
)

func main() {
	// BuildServerListSend("Sakura", "P127.0.0.1:12023,...")
	name := "Sakura"
	ip := "P127.0.0.1:12023,127.0.0.1:12023,127.0.0.1:12023,127.0.0.1:12023"
	
	nameBytes := []byte(name)
	ipBytes := []byte(ip)
	
	nameLen := len(nameBytes) + 1 // +1 untuk \0
	ipLen := len(ipBytes) + 1
	
	totalLen := 2 + 1 + nameLen + 1 + ipLen
	buf := make([]byte, totalLen)
	
	offset := 2 // padding
	
	// Name length
	buf[offset] = byte(nameLen)
	offset++
	
	// Name bytes + \0
	copy(buf[offset:], nameBytes)
	offset += len(nameBytes)
	buf[offset] = 0
	offset++
	
	// IP length
	buf[offset] = byte(ipLen)
	offset++
	
	// IP bytes + \0
	copy(buf[offset:], ipBytes)
	offset += len(ipBytes)
	buf[offset] = 0
	
	fmt.Println("=== SERVER LIST SEND PACKET ===")
	fmt.Printf("Name: %s\n", name)
	fmt.Printf("IP: %s\n", ip)
	fmt.Printf("Total length: %d bytes\n\n", totalLen)
	fmt.Printf("Packet (hex): %02X\n\n", buf)
	
	fmt.Println("Breakdown:")
	fmt.Printf("Offset 0-1: Padding = %02X %02X\n", buf[0], buf[1])
	fmt.Printf("Offset 2: nameLen = %d\n", buf[2])
	fmt.Printf("Offset 3-%d: name = %s\n", 3+len(nameBytes), string(buf[3:3+len(nameBytes)]))
	fmt.Printf("Offset %d: null = %02X\n", 3+len(nameBytes), buf[3+len(nameBytes)])
	fmt.Printf("Offset %d: ipLen = %d\n", 3+nameLen, buf[3+nameLen])
	fmt.Printf("Offset %d-%d: ip = %s\n", 4+nameLen, 4+nameLen+len(ipBytes), string(buf[4+nameLen:4+nameLen+len(ipBytes)]))
}
