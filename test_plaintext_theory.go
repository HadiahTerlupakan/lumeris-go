package main
import (
	"crypto/sha1"
	"fmt"
)

func main() {
	// From our log:
	// Front: 1950729824 (0x7445C660)
	// Back:  2749064412 (0xA3DB64DC)
	// Client SHA1: 9b6bff95eef22dde49f7814681c883e0bae6f00a
	
	front := uint32(1950729824)
	back := uint32(2749064412)
	clientSHA1 := "9b6bff95eef22dde49f7814681c883e0bae6f00a"
	
	fmt.Println("=== THEORY: Password in DB is PLAINTEXT ===\n")
	
	// If C# DB stores plaintext "pass9999":
	// Challenge: front(dec) + "pass9999" + back(dec)
	password := "pass9999"
	str := fmt.Sprintf("%d%s%d", front, password, back)
	hash := fmt.Sprintf("%x", sha1.Sum([]byte(str)))
	
	fmt.Printf("Password: %s\n", password)
	fmt.Printf("Challenge string: %s\n", str)
	fmt.Printf("Expected SHA1: %s\n", hash)
	fmt.Printf("Client SHA1:   %s\n", clientSHA1)
	fmt.Printf("Match: %v\n\n", hash == clientSHA1)
	
	if hash == clientSHA1 {
		fmt.Println("✅ SUCCESS! C# stores PLAINTEXT password!")
		fmt.Println("\nPROBLEM: Go server stores MD5 hash, not plaintext!")
		fmt.Println("SOLUTION: Change Go to store plaintext OR change challenge to use MD5")
	} else {
		fmt.Println("❌ Still no match. Need more investigation.")
	}
}
