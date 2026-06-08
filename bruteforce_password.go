package main
import (
	"crypto/md5"
	"crypto/sha1"
	"fmt"
)

func main() {
	front := uint32(1496071116)
	back := uint32(3854248468)
	targetSHA1 := "411b49e106bcc0483309e86268c5121c7b7a45e0"
	
	// Common passwords
	passwords := []string{
		"test123", "testlogin", "123456", "password", "admin", "test",
		"12345", "123456789", "qwerty", "abc123", "password123",
		"", "guest", "user", "demo", "login", "welcome", "pass",
		"1234", "12345678", "111111", "123123", "1234567", "123321",
		"654321", "root", "toor", "master", "ninja", "azerty",
	}
	
	fmt.Println("=== BRUTEFORCE: Find password that matches client SHA1 ===\n")
	fmt.Printf("Target SHA1: %s\n\n", targetSHA1)
	
	for _, pw := range passwords {
		md5Hash := fmt.Sprintf("%x", md5.Sum([]byte(pw)))
		
		// Try decimal format
		challengeStr := fmt.Sprintf("%d%s%d", front, md5Hash, back)
		sha1Hash := fmt.Sprintf("%x", sha1.Sum([]byte(challengeStr)))
		
		if sha1Hash == targetSHA1 {
			fmt.Printf("✅ FOUND with MD5!\n")
			fmt.Printf("Password: '%s'\n", pw)
			fmt.Printf("MD5: %s\n", md5Hash)
			fmt.Printf("Challenge: %s\n", challengeStr)
			return
		}
		
		// Try plaintext
		challengeStr2 := fmt.Sprintf("%d%s%d", front, pw, back)
		sha1Hash2 := fmt.Sprintf("%x", sha1.Sum([]byte(challengeStr2)))
		
		if sha1Hash2 == targetSHA1 {
			fmt.Printf("✅ FOUND with plaintext!\n")
			fmt.Printf("Password: '%s'\n", pw)
			fmt.Printf("Challenge: %s\n", challengeStr2)
			return
		}
	}
	
	fmt.Println("❌ Password not found in common list!")
	fmt.Println("\nPossible reasons:")
	fmt.Println("1. User typed WRONG password in client")
	fmt.Println("2. Client cached old password from previous session")
	fmt.Println("3. Client using completely different ECO protocol version")
}
