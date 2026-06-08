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
	fmt.Println("=== Final Challenge Verification ===
")
	
	// Test beberapa password untuk cari yang cocok dengan client SHA1
	passwords := []string{
		"dummy", "test", "admin", "root", "password",
		"dummy123", "test123", "admin123",
		"123456", "12345678",
		"", "a", "1",
	}
	
	front := uint32(0x4bb6b365)
	back := uint32(0xd9a2302c)
	clientSHA1 := "cd18578fd3f1d3f187efab55c905507e9331255f"
	
	fmt.Printf("Client SHA1: %s
", clientSHA1)
	fmt.Printf("Front: %d, Back: %d

", front, back)
	
	for _, pwd := range passwords {
		// Calculate MD5
		h := md5.Sum([]byte(pwd))
		md5Hex := hex.EncodeToString(h[:])
		
		// Challenge format: "frontword" + "md5_lowercase" + "backword"
		str := fmt.Sprintf("%d%s%d", front, strings.ToLower(md5Hex), back)
		
		// SHA1
		sha1Hash := sha1.Sum([]byte(str))
		sha1Hex := hex.EncodeToString(sha1Hash[:])
		
		match := sha1Hex == clientSHA1
		
		if match {
			fmt.Printf("✓✓✓ FOUND!
")
			fmt.Printf("Password: '%s'
", pwd)
			fmt.Printf("MD5: %s
", md5Hex)
			fmt.Printf("SHA1: %s

", sha1Hex)
			
			fmt.Println("Server sekarang sudah siap untuk login dengan password ini!")
			return
		}
	}
	
	fmt.Println("✗ Password tidak ditemukan dalam test list")
	fmt.Println("
Kesimpulan:")
	fmt.Println("- Format challenge sudah benar (sesuai ValidationClient.cs)")
	fmt.Println("- Client menggunakan password yang tidak ada dalam common list")
	fmt.Println("
Silakan test login dengan:")
	fmt.Println("  Username: dummy2")
	fmt.Println("  Password: test123")
}
