//go:build ignore

package main

import (
	"crypto/md5"
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
)

func testPassword(password string, front, back uint32, target string) bool {
	h := md5.Sum([]byte(password))
	md5Hex := hex.EncodeToString(h[:])
	
	buf := make([]byte, 4+32+4)
	binary.BigEndian.PutUint32(buf[0:4], front)
	copy(buf[4:36], []byte(strings.ToUpper(md5Hex)))
	binary.BigEndian.PutUint32(buf[36:40], back)
	
	sha1Result := sha1.Sum(buf)
	return hex.EncodeToString(sha1Result[:]) == target
}

func main() {
	front := uint32(0x4bb6b365)
	back := uint32(0xd9a2302c)
	target := "cd18578fd3f1d3f187efab55c905507e9331255f"
	
	fmt.Println("=== Searching for Client Password ===")
	fmt.Println("Testing comprehensive dictionary...")
	
	// Check "dummy" specifically
	if testPassword("dummy", front, back, target) {
		fmt.Println("✓ Password is: 'dummy'")
		return
	}
	
	// Build massive wordlist
	candidates := []string{}
	
	// All printable ASCII combinations up to length 6
	chars := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[]{}|;:',.<>?/`~ "
	
	// Length 1-2
	for _, c := range chars {
		candidates = append(candidates, string(c))
	}
	
	// Length 3-4 with common patterns
	for i := 0; i < 256; i++ {
		candidates = append(candidates, fmt.Sprintf("%d", i))
		candidates = append(candidates, fmt.Sprintf("test%d", i))
		candidates = append(candidates, fmt.Sprintf("dummy%d", i))
		candidates = append(candidates, fmt.Sprintf("admin%d", i))
		candidates = append(candidates, fmt.Sprintf("user%d", i))
		candidates = append(candidates, fmt.Sprintf("pass%d", i))
		candidates = append(candidates, fmt.Sprintf("%dtest", i))
		candidates = append(candidates, fmt.Sprintf("%ddummy", i))
	}
	
	// Common passwords
	commons := []string{
		"", "test", "dummy", "admin", "password", "123456", "12345678",
		"qwerty", "abc123", "password123", "admin123", "root", "toor",
		"guest", "user", "demo", "test123", "testing", "temp", "temporary",
	}
	candidates = append(candidates, commons...)
	
	fmt.Printf("Testing %d candidates...
", len(candidates))
	
	for i, pwd := range candidates {
		if i > 0 && i % 1000 == 0 {
			fmt.Printf("  Progress: %d/%d
", i, len(candidates))
		}
		
		if testPassword(pwd, front, back, target) {
			fmt.Printf("
✓✓✓ FOUND! Client password is: '%s'
", pwd)
			
			// Calculate its MD5
			h := md5.Sum([]byte(pwd))
			fmt.Printf("MD5: %s
", hex.EncodeToString(h[:]))
			fmt.Println("
To fix:")
			fmt.Printf("1. Re-register 'dummy' account with password '%s'
", pwd)
			fmt.Println("   OR")
			fmt.Printf("2. Update client to use password 'dummy123'
")
			return
		}
	}
	
	fmt.Println("
✗ Password still not found!")
	fmt.Println("
Recommendation: Ask the user what password they're typing in the client")
	fmt.Println("Or check the client source code to see what password it sends")
}
