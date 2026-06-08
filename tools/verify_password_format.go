//go:build ignore

package main

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"strings"
)

func main() {
	// Dari log parsing packet:
	// Password (hex string): 'cd18578fd3f1d3f187efab55c905507e9331255f'
	// Ini adalah HEX STRING yang dikirim client (40 chars ASCII)
	
	// Di C# code, Password = enc.GetString(...) berarti di-parse sebagai ASCII string
	// Jadi passwordString adalah "cd18578fd3f1d3f187efab55c905507e9331255f" (40 char hex string)
	
	storedMD5 := "851fdee206c1eec10cee5ec8e8962af2"
	front := uint32(0x4bb6b365)
	back := uint32(0xd9a2302c)
	clientPasswordHexString := "cd18578fd3f1d3f187efab55c905507e9331255f" // Ini yang client kirim
	
	fmt.Println("=== Verifying Password Format ===")
	fmt.Println()
	fmt.Println("Theory: CheckPassword receives password as HEX STRING (40 chars),")
	fmt.Println("        not as raw 20 bytes SHA1.")
	fmt.Println()
	
	// Test: apakah CheckPassword membandingkan hex string secara langsung?
	// Format: frontword + storedMD5_lower + backword -> SHA1 -> convert to hex string
	
	str := fmt.Sprintf("%d%s%d", front, strings.ToLower(storedMD5), back)
	expected := sha1.Sum([]byte(str))
	expectedHex := hex.EncodeToString(expected[:])
	
	fmt.Printf("Challenge string: %s
", str)
	fmt.Printf("Expected SHA1 hex: %s
", expectedHex)
	fmt.Printf("Client sent:       %s
", clientPasswordHexString)
	fmt.Printf("Match: %v
", expectedHex == clientPasswordHexString)
	
	if expectedHex == clientPasswordHexString {
		fmt.Println("
✓ Format correct!")
	} else {
		fmt.Println("
✗ No match")
		fmt.Println("
Possible issue: Client is using a different password than 'dummy123'")
		fmt.Println("The stored MD5 '851fdee206c1eec10cee5ec8e8962af2' is for 'dummy123'")
		fmt.Println("But client computed SHA1 for a DIFFERENT password")
	}
}
