package main
import (
	"crypto/sha1"
	"fmt"
)

func main() {
	// Second attempt (FAILED)
	front := uint32(541509510)
	back := uint32(2314928819)
	md5Hash := "cc03e747a6afbbcbf8be7668acfebee5"
	
	expectedSHA1 := "b121c9f505296e71c8c6d661d65a2bdc74e0b9a9"
	clientSHA1 := "563710ae6092ff61058d66486d4e327d1183d37c"
	
	fmt.Println("=== DEBUG SECOND LOGIN ATTEMPT ===\n")
	fmt.Printf("Front: %d (0x%08X)\n", front, front)
	fmt.Printf("Back:  %d (0x%08X)\n", back, back)
	fmt.Printf("MD5:   %s\n\n", md5Hash)
	
	// Server calculation
	challengeStr := fmt.Sprintf("%d%s%d", front, md5Hash, back)
	serverSHA1 := fmt.Sprintf("%x", sha1.Sum([]byte(challengeStr)))
	
	fmt.Printf("Challenge string: %s\n", challengeStr)
	fmt.Printf("Server SHA1:      %s\n", serverSHA1)
	fmt.Printf("Expected SHA1:    %s\n", expectedSHA1)
	fmt.Printf("Client SHA1:      %s\n\n", clientSHA1)
	
	fmt.Printf("Server calculation correct: %v\n", serverSHA1 == expectedSHA1)
	fmt.Printf("Client matches expected:    %v\n", clientSHA1 == expectedSHA1)
	
	if clientSHA1 != expectedSHA1 {
		fmt.Println("\n❌ PROBLEM: Client sent DIFFERENT SHA1!")
		fmt.Println("\nPOSSIBLE CAUSES:")
		fmt.Println("1. Client is caching old front/back words from first attempt")
		fmt.Println("2. Client received corrupted LOGIN_ALLOWED packet")
		fmt.Println("3. Client using different MD5 (wrong password entered?)")
		fmt.Println("4. Network packet issue (encryption/decryption error)")
	}
}
