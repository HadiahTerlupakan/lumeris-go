//go:build ignore

package main

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"strings"
)

func main() {
	// Data dari log
	storedMD5 := "851fdee206c1eec10cee5ec8e8962af2" // MD5('dummy123')
	front := uint32(0x4bb6b365)  // 1270035301 decimal
	back := uint32(0xd9a2302c)   // 3651522604 decimal
	clientSHA1 := "cd18578fd3f1d3f187efab55c905507e9331255f"
	
	fmt.Println("=== Testing Fixed Challenge Format ===")
	fmt.Printf("Stored MD5: %s
", storedMD5)
	fmt.Printf("Front: %d (0x%08x)
", front, front)
	fmt.Printf("Back: %d (0x%08x)
", back, back)
	fmt.Printf("Client SHA1: %s

", clientSHA1)
	
	// Format baru: decimal_string + password_lowercase + decimal_string
	str := fmt.Sprintf("%d%s%d", front, strings.ToLower(storedMD5), back)
	expected := sha1.Sum([]byte(str))
	expectedHex := hex.EncodeToString(expected[:])
	
	fmt.Printf("Challenge string: %s
", str)
	fmt.Printf("Expected SHA1: %s
", expectedHex)
	fmt.Printf("Client SHA1:   %s
", clientSHA1)
	
	if expectedHex == clientSHA1 {
		fmt.Println("
✓✓✓ MATCH! Challenge format is correct!")
		fmt.Println("Login dengan username 'dummy' dan password 'dummy123' seharusnya berhasil.")
	} else {
		fmt.Println("
✗ Still no match - client might be using different password")
	}
}
