//go:build ignore

package main

import (
	"encoding/hex"
	"fmt"
)

func main() {
	// Raw packet dari log:
	// 0664756d6d790029636431383537386664336631643366313837656661623535633930353530376539333331323535660006f02f74cec12b00000000
	
	raw := "0664756d6d790029636431383537386664336631643366313837656661623535633930353530376539333331323535660006f02f74cec12b00000000"
	data, _ := hex.DecodeString(raw)
	
	fmt.Printf("Total length: %d bytes
", len(data))
	fmt.Printf("Raw hex: %s

", raw)
	
	offset := 0
	
	// Parse username
	uLen := int(data[offset])
	fmt.Printf("Username length byte: 0x%02x (%d)
", data[offset], uLen)
	offset++
	
	if offset+uLen > len(data) {
		fmt.Println("ERROR: Username overflow")
		return
	}
	
	username := string(data[offset : offset+uLen-1]) // -1 untuk null terminator
	fmt.Printf("Username: '%s' (bytes: %02x)
", username, data[offset:offset+uLen])
	offset += uLen
	
	// Parse password (should be hex string)
	if offset >= len(data) {
		fmt.Println("ERROR: No password data")
		return
	}
	
	pLen := int(data[offset])
	fmt.Printf("
Password length byte: 0x%02x (%d)
", data[offset], pLen)
	offset++
	
	if offset+pLen > len(data) {
		fmt.Println("ERROR: Password overflow")
		return
	}
	
	passwordHex := string(data[offset : offset+pLen-1]) // -1 untuk null terminator
	fmt.Printf("Password (hex string): '%s'
", passwordHex)
	fmt.Printf("Password bytes: %02x
", data[offset:offset+pLen])
	
	// Convert hex string to bytes
	passwordBytes := make([]byte, len(passwordHex)/2)
	for i := 0; i < len(passwordHex); i += 2 {
		fmt.Sscanf(passwordHex[i:i+2], "%02x", &passwordBytes[i/2])
	}
	fmt.Printf("Password as bytes: %02x (len=%d)
", passwordBytes, len(passwordBytes))
	offset += pLen
	
	// Parse MAC
	if offset+6 > len(data) {
		fmt.Println("ERROR: No MAC data")
		return
	}
	
	mac := data[offset : offset+6]
	fmt.Printf("
MAC address: %02x
", mac)
	offset += 6
	
	// Remaining data
	if offset < len(data) {
		fmt.Printf("
Remaining bytes: %02x
", data[offset:])
	}
	
	fmt.Println("
=== Summary ===")
	fmt.Printf("Username: '%s'
", username)
	fmt.Printf("Password SHA1: %s
", hex.EncodeToString(passwordBytes))
	fmt.Printf("MAC: %02x
", mac)
}
