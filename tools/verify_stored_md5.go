//go:build ignore

package main

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
)

func main() {
	// MD5 yang tersimpan di DB untuk user 'dummy'
	storedMD5 := "851fdee206c1eec10cee5ec8e8962af2"
	
	fmt.Println("=== Verify what password produces this MD5 ===")
	fmt.Printf("Stored MD5: %s

", storedMD5)
	
	// Test reverse - coba cari password yang menghasilkan MD5 ini
	// dengan wordlist lebih detail
	
	wordlist := []string{
		// Karakter tunggal dan repetisi
		"a", "b", "c", "d", "e", "f", "g", "h", "i", "j",
		"aa", "bb", "cc", "dd", "ee",
		"aaa", "bbb", "ccc", "ddd",
		"aaaa", "bbbb", "cccc", "dddd",
		
		// Angka
		"0", "1", "2", "3", "4", "5", "6", "7", "8", "9",
		"00", "11", "22", "33", "44", "55", "66", "77", "88", "99",
		"000", "111", "222", "333", "444", "555",
		"0000", "1111", "2222", "3333", "4444", "5555",
		
		// Common words
		"test", "demo", "dummy", "admin", "user", "guest", "root",
		"password", "pass", "pwd", "secret", "login",
		
		// Numbers
		"1", "12", "123", "1234", "12345", "123456", "1234567", "12345678",
		"0123456789",
		
		// Combinations
		"test1", "test12", "test123", "test1234",
		"admin1", "admin12", "admin123",
		"dummy1", "dummy12", "dummy123",
		"user1", "user12", "user123",
		"password1", "password123",
		
		// Empty and spaces
		"", " ", "  ", "   ",
	}
	
	found := false
	for _, pw := range wordlist {
		h := md5.Sum([]byte(pw))
		calculatedMD5 := hex.EncodeToString(h[:])
		
		if calculatedMD5 == storedMD5 {
			fmt.Printf("✓✓✓ FOUND THE ORIGINAL PASSWORD!
")
			fmt.Printf("Password: '%s'
", pw)
			fmt.Printf("MD5: %s
", calculatedMD5)
			found = true
			break
		}
	}
	
	if !found {
		fmt.Println("✗ Password not in wordlist")
		fmt.Println("
The account 'dummy' was registered with a password not in common wordlist.")
		fmt.Println("Recommendation:")
		fmt.Println("1. Delete the 'dummy' account from database")
		fmt.Println("2. Re-register with a known password (e.g., 'test123')")
		fmt.Println("3. Try login again with that password")
	}
}
