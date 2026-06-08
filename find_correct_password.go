package main
import (
	"crypto/md5"
	"crypto/sha1"
	"fmt"
)

func main() {
	front := uint32(1950729824)
	back := uint32(2749064412)
	targetSHA1 := "9b6bff95eef22dde49f7814681c883e0bae6f00a"
	
	fmt.Println("=== BRUTE FORCE: Find correct password ===\n")
	
	// Try common passwords for user9999
	passwords := []string{
		"pass9999", "9999", "user9999", "password", "test", "test123",
		"123456", "admin", "demo", "", "1234", "12345", "123456789",
		"password123", "qwerty", "abc123", "Pass9999", "USER9999",
		"pass", "user", "guest", "player", "login", "welcome",
	}
	
	for _, pw := range passwords {
		md5Hash := fmt.Sprintf("%x", md5.Sum([]byte(pw)))
		challengeStr := fmt.Sprintf("%d%s%d", front, md5Hash, back)
		sha1Hash := fmt.Sprintf("%x", sha1.Sum([]byte(challengeStr)))
		
		if sha1Hash == targetSHA1 {
			fmt.Printf("✅ FOUND!\n")
			fmt.Printf("Password: '%s'\n", pw)
			fmt.Printf("MD5:      %s\n", md5Hash)
			fmt.Printf("Challenge: %s\n", challengeStr)
			fmt.Printf("SHA1:      %s\n\n", sha1Hash)
			
			fmt.Println("ACTION REQUIRED:")
			fmt.Printf("Update database: UPDATE accounts SET password_hash='%s' WHERE username='user9999';\n", md5Hash)
			return
		}
	}
	
	fmt.Println("❌ Password not found in common list!")
	fmt.Println("\nSuggestion: Buat account baru dengan password yang kamu tahu:")
	fmt.Println("curl -X POST http://127.0.0.1:8001/register -H 'username: testuser2' -H 'password: test123'")
}
