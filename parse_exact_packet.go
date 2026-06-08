package main
import (
	"encoding/hex"
	"fmt"
)

func main() {
	// From log line 14:
	// [Validation] OnLogin received 63 bytes: 
	// 0975736572393939390029396236626666393565656632326464653439663738313436383163383833653062616536663030610006f02f74cec12b00000000
	
	packetHex := "0975736572393939390029396236626666393565656632326464653439663738313436383163383833653062616536663030610006f02f74cec12b00000000"
	data, _ := hex.DecodeString(packetHex)
	
	fmt.Println("=== PARSE CSMG_LOGIN PACKET ===\n")
	fmt.Printf("Total length: %d bytes\n\n", len(data))
	
	offset := 0
	
	// Username length
	uLen := int(data[offset])
	fmt.Printf("Username length byte: 0x%02X = %d\n", uLen, uLen)
	offset++
	
	// Username string (uLen - 1, excluding null terminator)
	username := string(data[offset : offset+uLen-1])
	fmt.Printf("Username: '%s' (%d chars)\n", username, len(username))
	offset += uLen // including null terminator
	
	fmt.Printf("After username, offset = %d\n\n", offset)
	
	// Password length
	pLen := int(data[offset])
	fmt.Printf("Password length byte: 0x%02X = %d\n", pLen, pLen)
	offset++
	
	// Password string (pLen - 1, excluding null terminator)
	passwordHex := string(data[offset : offset+pLen-1])
	fmt.Printf("Password (hex string): '%s' (%d chars)\n", passwordHex, len(passwordHex))
	offset += pLen // including null terminator
	
	fmt.Printf("After password, offset = %d\n\n", offset)
	
	// MAC address (6 bytes: ushort + uint)
	if offset+6 <= len(data) {
		mac := data[offset : offset+6]
		fmt.Printf("MAC address: %02x:%02x:%02x:%02x:%02x:%02x\n\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5])
	}
	
	fmt.Println("=== CLIENT SENT SHA1 ===")
	fmt.Printf("SHA1: %s\n", passwordHex)
}
