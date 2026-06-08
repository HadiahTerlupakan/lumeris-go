//go:build ignore

package main

import (
	"bufio"
	"crypto/md5"
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
)

func main() {
	fmt.Println("=== ECO Login Password Diagnostic Tool ===")
	fmt.Println()
	fmt.Println("This tool helps verify what password the client is using.")
	fmt.Println()

	// Data dari log terakhir
	fmt.Println("From server log:")
	fmt.Println("  Username: dummy")
	fmt.Println("  Front challenge: 4bb6b365")
	fmt.Println("  Back challenge: d9a2302c")
	fmt.Println("  Client sent SHA1: cd18578fd3f1d3f187efab55c905507e9331255f")
	fmt.Println()

	reader := bufio.NewReader(os.Stdin)

	for {
		fmt.Print("Enter password to test (or 'quit' to exit): ")
		input, _ := reader.ReadString('
')
		password := strings.TrimSpace(input)

		if password == "quit" || password == "exit" {
			break
		}

		// Calculate MD5
		h := md5.Sum([]byte(password))
		md5Hex := hex.EncodeToString(h[:])

		// Calculate SHA1 challenge response
		front := uint32(0x4bb6b365)
		back := uint32(0xd9a2302c)

		buf := make([]byte, 4+32+4)
		binary.BigEndian.PutUint32(buf[0:4], front)
		copy(buf[4:36], []byte(strings.ToUpper(md5Hex)))
		binary.BigEndian.PutUint32(buf[36:40], back)

		sha1Result := sha1.Sum(buf)
		sha1Hex := hex.EncodeToString(sha1Result[:])

		fmt.Printf("
  Password: '%s'
", password)
		fmt.Printf("  MD5: %s
", md5Hex)
		fmt.Printf("  Calculated SHA1: %s
", sha1Hex)
		fmt.Printf("  Client SHA1:     cd18578fd3f1d3f187efab55c905507e9331255f
")

		if sha1Hex == "cd18578fd3f1d3f187efab55c905507e9331255f" {
			fmt.Println("  ✓✓✓ MATCH! This is the correct password!")
		} else {
			fmt.Println("  ✗ No match")
		}
		fmt.Println()
	}

	fmt.Println("
Quick fix options:")
	fmt.Println("1. Use 'test123' as password (account 'dummy2' already registered)")
	fmt.Println("2. Find the correct password using this tool")
	fmt.Println("3. Check what password your ECO client is configured to use")
}
