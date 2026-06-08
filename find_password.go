package main
import (
	"crypto/md5"
	"fmt"
)

func main() {
	targetMD5 := "57b2f4c72fd9e904593453cfed3ef751"
	
	// Common test passwords
	passwords := []string{
		"user9999", "9999", "test", "test123", "password", 
		"123456", "admin", "user", "demo", "pass9999",
		"", // empty password
	}
	
	fmt.Println("=== Trying common passwords ===")
	for _, pw := range passwords {
		hash := fmt.Sprintf("%x", md5.Sum([]byte(pw)))
		if hash == targetMD5 {
			fmt.Printf("✅ FOUND! Password: '%s' -> MD5: %s\n", pw, hash)
			return
		}
		fmt.Printf("   '%s' -> %s (no match)\n", pw, hash)
	}
	
	fmt.Println("\n❌ Password tidak ditemukan di common passwords")
	fmt.Println("Coba kasih tau password yang kamu tahu untuk user9999?")
}
