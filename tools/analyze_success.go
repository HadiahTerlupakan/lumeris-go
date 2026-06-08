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
	// From successful login at 17:09:39
	password := "test123"
	front := uint32(0x35bef832) // 901707826
	back := uint32(0x2178028e)  // 561513102
	clientSHA1 := "3e0de76b41a0761bff90330772e1f796da4fa378"
	
	// Calculate
	h := md5.Sum([]byte(password))
	md5Hex := hex.EncodeToString(h[:])
	
	str := fmt.Sprintf("%d%s%d", front, strings.ToLower(md5Hex), back)
	expected := sha1.Sum([]byte(str))
	expectedHex := hex.EncodeToString(expected[:])
	
	fmt.Println("=== Analyzing SUCCESSFUL Login (17:09:39) ===")
	fmt.Printf("Password: %s
", password)
	fmt.Printf("MD5: %s
", md5Hex)
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
✓✓✓ That login WAS correct!")
		fmt.Println("The formula is RIGHT!")
	}
}
