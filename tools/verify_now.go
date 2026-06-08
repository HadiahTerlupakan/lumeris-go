//go:build ignore

package main

import (
	"crypto/md5"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"strings"
)

func main() {
	// From latest log
	password := "test123"
	front := uint32(0x96f4529e) // 2532594334
	back := uint32(0x5dd282cd)  // 1574077133
	clientSHA1 := "690d29a9a7c3158792bc3d45a41cf1e4e11afc50"
	
	// Calculate MD5
	h := md5.Sum([]byte(password))
	md5Hex := hex.EncodeToString(h[:])
	
	// Calculate expected SHA1
	str := fmt.Sprintf("%d%s%d", front, strings.ToLower(md5Hex), back)
	expected := sha1.Sum([]byte(str))
	expectedHex := hex.EncodeToString(expected[:])
	
	fmt.Println("=== Verification ===")
	fmt.Printf("Password: %s
", password)
	fmt.Printf("MD5: %s
", md5Hex)
	fmt.Printf("Front: %d
", front)
	fmt.Printf("Back: %d
", back)
	fmt.Printf("Challenge string: %s
", str)
	fmt.Printf("Expected SHA1: %s
", expectedHex)
	fmt.Printf("Client SHA1:   %s
", clientSHA1)
	fmt.Printf("Match: %v
", expectedHex == clientSHA1)
	
	if expectedHex == clientSHA1 {
		fmt.Println("
✓ Formula is CORRECT!")
	} else {
		fmt.Println("
✗ Something is wrong")
		fmt.Println("
Maybe client is using a DIFFERENT password?")
		fmt.Println("Or there's still a bug in the challenge calculation?")
	}
}
