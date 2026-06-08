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
	// MD5 hash in DB: 57b2f4c72fd9e904593453cfed3ef751
	
	front := uint32(1950729824)
	back := uint32(2749064412)
	clientSHA1 := "9b6bff95eef22dde49f7814681c883e0bae6f00a"
	md5Hash := "57b2f4c72fd9e904593453cfed3ef751"
	
	fmt.Println("=== TEST: Different MD5 formats ===\n")
	
	// Test 1: front(dec) + md5(lowercase) + back(dec)
	str1 := fmt.Sprintf("%d%s%d", front, md5Hash, back)
	hash1 := fmt.Sprintf("%x", sha1.Sum([]byte(str1)))
	fmt.Printf("1. front(dec) + md5 + back(dec)\n")
	fmt.Printf("   String: %s\n", str1)
	fmt.Printf("   SHA1:   %s\n", hash1)
	fmt.Printf("   Match:  %v\n\n", hash1 == clientSHA1)
	
	// Test 2: front(dec) + md5(UPPERCASE) + back(dec)
	md5Upper := "57B2F4C72FD9E904593453CFED3EF751"
	str2 := fmt.Sprintf("%d%s%d", front, md5Upper, back)
	hash2 := fmt.Sprintf("%x", sha1.Sum([]byte(str2)))
	fmt.Printf("2. front(dec) + MD5(UPPER) + back(dec)\n")
	fmt.Printf("   String: %s\n", str2)
	fmt.Printf("   SHA1:   %s\n", hash2)
	fmt.Printf("   Match:  %v\n\n", hash2 == clientSHA1)
	
	// Test 3: Maybe client uses different password format?
	// Let me check if password field in C# is NOT MD5 but something else
	
	// WAIT - let me check the actual packet bytes from log
	// From log: 0975736572393939390029396236626666393565656632326464653439663738313436383163383833653062616536663030610006f02f74cec12b00000000
	// 09 = length of username (9 bytes)
	// 75736572393939 = "user999" in hex? Let me decode
	username := "user9999" // 9 bytes
	fmt.Printf("Username from packet: %s (length should be 9)\n", username)
	fmt.Printf("Actual length: %d\n\n", len(username))
	
	// Password hex from packet: 29 = length (41 bytes)
	// 396236626666393565656632326464653439663738313436383163383833653062616536663030610006f02f74cec12b00000000
	// Wait, 0x29 = 41 decimal
	// But SHA1 hex string is 40 chars + null = 41 bytes
	// So password field is: 9b6bff95eef22dde49f7814681c883e0bae6f00a
	
	// This confirms client SHA1 is correct
	// Now I need to find what string produces this SHA1
	
	fmt.Println("=== HYPOTHESIS: Maybe password stored is already hashed differently ===")
	fmt.Println("Let me check C# GetUser to see what 'password' field contains...")
}
