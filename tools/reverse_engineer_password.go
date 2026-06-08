//go:build ignore

package main

import (
	"crypto/md5"
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
)

func main() {
	// Target: client SHA1
	targetSHA1 := "cd18578fd3f1d3f187efab55c905507e9331255f"
	front := uint32(0x4bb6b365)
	back := uint32(0xd9a2302c)
	
	fmt.Println("=== Reverse Engineering Client Password ===")
	fmt.Printf("Target SHA1: %s
", targetSHA1)
	fmt.Printf("Front: %08x, Back: %08x

", front, back)
	
	// Generate comprehensive wordlist
	wordlist := make([]string, 0, 10000)
	
	// Single chars
	for c := 'a'; c <= 'z'; c++ {
		wordlist = append(wordlist, string(c))
	}
	for c := 'A'; c <= 'Z'; c++ {
		wordlist = append(wordlist, string(c))
	}
	for c := '0'; c <= '9'; c++ {
		wordlist = append(wordlist, string(c))
	}
	
	// Numbers 0-9999
	for i := 0; i < 10000; i++ {
		wordlist = append(wordlist, fmt.Sprintf("%d", i))
	}
	
	// Common words
	commonWords := []string{
		"test", "demo", "dummy", "admin", "user", "guest", "root", "password",
		"pass", "pwd", "secret", "login", "qwerty", "abc", "xyz",
	}
	
	// Add variations
	for _, word := range commonWords {
		wordlist = append(wordlist, word)
		wordlist = append(wordlist, strings.ToUpper(word))
		wordlist = append(wordlist, strings.Title(word))
		for i := 0; i < 1000; i++ {
			wordlist = append(wordlist, fmt.Sprintf("%s%d", word, i))
			wordlist = append(wordlist, fmt.Sprintf("%d%s", i, word))
		}
	}
	
	fmt.Printf("Testing %d passwords...
", len(wordlist))
	
	tested := 0
	for _, password := range wordlist {
		tested++
		if tested % 10000 == 0 {
			fmt.Printf("  Tested: %d...
", tested)
		}
		
		// Calculate MD5
		h := md5.Sum([]byte(password))
		md5Hex := hex.EncodeToString(h[:])
		
		// Build buffer
		buf := make([]byte, 4+32+4)
		binary.BigEndian.PutUint32(buf[0:4], front)
		copy(buf[4:36], []byte(strings.ToUpper(md5Hex)))
		binary.BigEndian.PutUint32(buf[36:40], back)
		
		// Calculate SHA1
		sha1Result := sha1.Sum(buf)
		sha1ResultHex := hex.EncodeToString(sha1Result[:])
		
		if sha1ResultHex == targetSHA1 {
			fmt.Printf("
✓✓✓ PASSWORD FOUND! ✓✓✓
")
			fmt.Printf("Password: '%s'
", password)
			fmt.Printf("MD5: %s
", md5Hex)
			fmt.Printf("SHA1: %s
", sha1ResultHex)
			return
		}
	}
	
	fmt.Println("
✗ Password not found in wordlist")
	fmt.Println("
Possible reasons:")
	fmt.Println("1. Client used a password not in the wordlist")
	fmt.Println("2. Client is using a different challenge format")
	fmt.Println("3. There's a bug in the client code")
}
