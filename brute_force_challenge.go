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
	
	password := "pass9999"
	md5Hash := fmt.Sprintf("%x", md5.Sum([]byte(password)))
	
	fmt.Println("=== BRUTE FORCE: Try ALL possible format combinations ===\n")
	fmt.Printf("Front: %d (0x%08X)\n", front, front)
	fmt.Printf("Back:  %d (0x%08X)\n", back, back)
	fmt.Printf("Password plaintext: %s\n", password)
	fmt.Printf("Password MD5: %s\n", md5Hash)
	fmt.Printf("Target SHA1: %s\n\n", targetSHA1)
	
	tests := []struct{
		name string
		str  string
	}{
		// Decimal formats
		{"front(dec) + password + back(dec)", fmt.Sprintf("%d%s%d", front, password, back)},
		{"front(dec) + md5 + back(dec)", fmt.Sprintf("%d%s%d", front, md5Hash, back)},
		{"back(dec) + password + front(dec)", fmt.Sprintf("%d%s%d", back, password, front)},
		{"back(dec) + md5 + front(dec)", fmt.Sprintf("%d%s%d", back, md5Hash, front)},
		
		// Hex formats (lowercase)
		{"front(hex) + password + back(hex)", fmt.Sprintf("%08x%s%08x", front, password, back)},
		{"front(hex) + md5 + back(hex)", fmt.Sprintf("%08x%s%08x", front, md5Hash, back)},
		{"back(hex) + password + front(hex)", fmt.Sprintf("%08x%s%08x", back, password, front)},
		{"back(hex) + md5 + front(hex)", fmt.Sprintf("%08x%s%08x", back, md5Hash, front)},
		
		// Hex formats (UPPERCASE)
		{"FRONT(HEX) + password + BACK(HEX)", fmt.Sprintf("%08X%s%08X", front, password, back)},
		{"FRONT(HEX) + MD5 + BACK(HEX)", fmt.Sprintf("%08X%s%08X", front, md5Hash, back)},
		
		// Maybe password field in C# DB is UPPERCASE MD5?
		{"front(dec) + MD5(UPPER) + back(dec)", fmt.Sprintf("%d%s%d", front, "57B2F4C72FD9E904593453CFED3EF751", back)},
		{"FRONT(HEX) + MD5(UPPER) + BACK(HEX)", fmt.Sprintf("%08X%s%08X", front, "57B2F4C72FD9E904593453CFED3EF751", back)},
	}
	
	for i, test := range tests {
		hash := fmt.Sprintf("%x", sha1.Sum([]byte(test.str)))
		match := hash == targetSHA1
		status := "❌"
		if match {
			status = "✅ MATCH!"
		}
		fmt.Printf("%2d. %s %s\n", i+1, status, test.name)
		if match {
			fmt.Printf("    String: %s\n", test.str)
			fmt.Printf("    SHA1:   %s\n\n", hash)
			return
		}
	}
	
	fmt.Println("\n❌ No match found in common formats!")
	fmt.Println("Need to check C# database schema to see what's stored in 'password' column")
}
