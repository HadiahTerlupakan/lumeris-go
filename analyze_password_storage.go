package main
import (
	"crypto/md5"
	"crypto/sha1"
	"fmt"
)

func main() {
	// user9999 password: pass9999
	// Stored in DB: 57b2f4c72fd9e904593453cfed3ef751
	
	password := "pass9999"
	md5Hash := fmt.Sprintf("%x", md5.Sum([]byte(password)))
	
	fmt.Println("=== ANALYZE PASSWORD STORAGE ===\n")
	fmt.Printf("Plaintext password: %s\n", password)
	fmt.Printf("MD5(password):      %s\n", md5Hash)
	fmt.Printf("Stored in Go DB:    57b2f4c72fd9e904593453cfed3ef751\n")
	fmt.Printf("Match: %v\n\n", md5Hash == "57b2f4c72fd9e904593453cfed3ef751")
	
	// OK so storage is correct (MD5 hex)
	// Now let's test the challenge with EXACT C# format
	
	front := uint32(1950729824)
	back := uint32(2749064412)
	clientSHA1 := "9b6bff95eef22dde49f7814681c883e0bae6f00a"
	
	fmt.Println("=== TEST C# FORMAT EXACTLY ===")
	fmt.Println("C# Code: string.Format(\"{0}{1}{2}\", frontword, password.ToLower(), backword)")
	fmt.Println("")
	
	// C# string.Format with {0}{1}{2}
	challengeStr := fmt.Sprintf("%d%s%d", front, md5Hash, back)
	expectedSHA1 := fmt.Sprintf("%x", sha1.Sum([]byte(challengeStr)))
	
	fmt.Printf("Challenge string: %s\n", challengeStr)
	fmt.Printf("Expected SHA1:    %s\n", expectedSHA1)
	fmt.Printf("Client SHA1:      %s\n", clientSHA1)
	fmt.Printf("Match: %v\n\n", expectedSHA1 == clientSHA1)
	
	if expectedSHA1 != clientSHA1 {
		fmt.Println("❌ STILL NO MATCH!")
		fmt.Println("\nPOSSIBLE REASONS:")
		fmt.Println("1. Client password is DIFFERENT from 'pass9999'")
		fmt.Println("2. Client is using DIFFERENT ECO version with different auth")
		fmt.Println("3. Database password for user9999 is WRONG")
		fmt.Println("\nLet me try to REVERSE ENGINEER what password produces client SHA1...")
	}
}
