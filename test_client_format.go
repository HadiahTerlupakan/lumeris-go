package main
import (
	"crypto/sha1"
	"fmt"
)

func main() {
	front := uint32(1950729824)
	back := uint32(2749064412)
	md5 := "57b2f4c72fd9e904593453cfed3ef751"
	clientSHA1 := "9b6bff95eef22dde49f7814681c883e0bae6f00a"
	
	fmt.Println("=== Testing Different Challenge Formats ===\n")
	
	// Format 1: front(decimal) + md5 + back(decimal)
	fmt.Println("1. Server format: front(dec) + md5 + back(dec)")
	str1 := fmt.Sprintf("%d%s%d", front, md5, back)
	hash1 := fmt.Sprintf("%x", sha1.Sum([]byte(str1)))
	fmt.Printf("   String: %s\n", str1)
	fmt.Printf("   SHA1:   %s\n", hash1)
	fmt.Printf("   Match:  %v\n\n", hash1 == clientSHA1)
	
	// Format 2: front(hex) + md5 + back(hex)
	fmt.Println("2. Format: front(hex) + md5 + back(hex)")
	str2 := fmt.Sprintf("%08x%s%08x", front, md5, back)
	hash2 := fmt.Sprintf("%x", sha1.Sum([]byte(str2)))
	fmt.Printf("   String: %s\n", str2)
	fmt.Printf("   SHA1:   %s\n", hash2)
	fmt.Printf("   Match:  %v\n\n", hash2 == clientSHA1)
	
	// Format 3: front(hex uppercase) + MD5(uppercase) + back(hex uppercase)
	fmt.Println("3. Format: FRONT(HEX) + MD5(UPPER) + BACK(HEX)")
	str3 := fmt.Sprintf("%08X%s%08X", front, "57B2F4C72FD9E904593453CFED3EF751", back)
	hash3 := fmt.Sprintf("%x", sha1.Sum([]byte(str3)))
	fmt.Printf("   String: %s\n", str3)
	fmt.Printf("   SHA1:   %s\n", hash3)
	fmt.Printf("   Match:  %v\n\n", hash3 == clientSHA1)
	
	// Format 4: back + md5 + front (reversed order)
	fmt.Println("4. Format: back(dec) + md5 + front(dec) [REVERSED]")
	str4 := fmt.Sprintf("%d%s%d", back, md5, front)
	hash4 := fmt.Sprintf("%x", sha1.Sum([]byte(str4)))
	fmt.Printf("   String: %s\n", str4)
	fmt.Printf("   SHA1:   %s\n", hash4)
	fmt.Printf("   Match:  %v\n\n", hash4 == clientSHA1)
}
