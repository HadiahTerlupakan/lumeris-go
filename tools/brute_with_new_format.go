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
	front := uint32(0x4bb6b365)
	back := uint32(0xd9a2302c)
	targetHex := "cd18578fd3f1d3f187efab55c905507e9331255f"
	
	fmt.Println("=== Brute Force with Correct Format ===")
	
	passwords := []string{
		"dummy", "test", "admin", "password", "123456",
		"dummy123", "test123", "admin123",
		"", "a", "aa", "aaa", "aaaa",
		"1", "12", "123", "1234", "12345",
	}
	
	for _, pwd := range passwords {
		md5Hash := md5.Sum([]byte(pwd))
		md5Hex := hex.EncodeToString(md5Hash[:])
		
		str := fmt.Sprintf("%d%s%d", front, strings.ToLower(md5Hex), back)
		sha1Hash := sha1.Sum([]byte(str))
		sha1Hex := hex.EncodeToString(sha1Hash[:])
		
		if sha1Hex == targetHex {
			fmt.Printf("
✓✓✓ FOUND! Password: '%s'
", pwd)
			fmt.Printf("MD5: %s
", md5Hex)
			return
		}
	}
	
	fmt.Println("
✗ Password not found in list")
}
