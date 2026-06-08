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

func main() {
	// Data dari log
	front := uint32(0x4bb6b365)
	back := uint32(0xd9a2302c)
	clientSHA1, _ := hex.DecodeString("cd18578fd3f1d3f187efab55c905507e9331255f")
	
	fmt.Println("=== Extended Brute Force ===")
	fmt.Println("Trying more passwords...
")
	
	// Extended password list - fokus ke kata-kata terkait "dummy"
	passwords := []string{
		// Numeric
		"1", "12", "123", "1234", "12345", "123456", "1234567", "12345678",
		"0", "00", "000", "0000", "00000", "000000",
		
		// Simple words
		"a", "aa", "aaa", "aaaa", "aaaaa", "aaaaaa",
		"test", "demo", "dummy", "user", "admin", "guest", "root",
		"password", "pass", "pwd",
		
		// Common combinations
		"test1", "test12", "test123",
		"dummy1", "dummy12", "dummy123",
		"admin1", "admin123",
		
		// Empty or special
		"", " ", "  ",
	}
	
	found := false
	for _, plaintext := range passwords {
		h := md5.Sum([]byte(plaintext))
		calculatedMD5 := hex.EncodeToString(h[:])
		
		// Test dengan uppercase MD5 (format yang digunakan server)
		buf := make([]byte, 4+32+4)
		binary.BigEndian.PutUint32(buf[0:4], front)
		copy(buf[4:36], []byte(strings.ToUpper(calculatedMD5)))
		binary.BigEndian.PutUint32(buf[36:40], back)
		
		sha1Result := sha1.Sum(buf)
		
		// Compare
		match := true
		for i := 0; i < 20; i++ {
			if sha1Result[i] != clientSHA1[i] {
				match = false
				break
			}
		}
		
		if match {
			fmt.Printf("✓✓✓ FOUND!!!
")
			fmt.Printf("Password: '%s'
", plaintext)
			fmt.Printf("MD5: %s
", calculatedMD5)
			fmt.Printf("Buffer: %02x
", buf)
			fmt.Printf("SHA1: %02x
", sha1Result[:])
			found = true
			break
		}
	}
	
	if !found {
		fmt.Println("✗ Still not found")
		fmt.Println("
The stored MD5 in DB: 851fdee206c1eec10cee5ec8e8962af2")
		fmt.Println("Client SHA1:          cd18578fd3f1d3f187efab55c905507e9331255f")
		fmt.Println("
Conclusion: Either password was changed after registration,")
		fmt.Println("            or there's a mismatch in how password was stored vs verified.")
	}
}
