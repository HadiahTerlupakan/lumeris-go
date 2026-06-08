//go:build ignore

package main

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"strings"
)

func main() {
	// Simulate exact C# logic from line 247-250:
	// string str = string.Format("{0}{1}{2}", frontword, ((string)result[0]["password"]).ToLower(), backword);
	// buf = sha1.ComputeHash(System.Text.Encoding.ASCII.GetBytes(str));
	// var testpwd = Conversions.bytes2HexString(buf).ToLower();
	// return password == testpwd;
	
	// From packet log:
	// - Client sent password as hex string: "cd18578fd3f1d3f187efab55c905507e9331255f"
	// - Stored in DB: "851fdee206c1eec10cee5ec8e8962af2"
	// - Front: 0x4bb6b365 = 1270264677
	// - Back: 0xd9a2302c = 3651285036
	
	storedPasswordInDB := "851fdee206c1eec10cee5ec8e8962af2"
	frontword := uint32(0x4bb6b365)
	backword := uint32(0xd9a2302c)
	clientSentPassword := "cd18578fd3f1d3f187efab55c905507e9331255f"
	
	// Line 247: Build string
	str := fmt.Sprintf("%d%s%d", frontword, strings.ToLower(storedPasswordInDB), backword)
	
	// Line 248: SHA1
	buf := sha1.Sum([]byte(str))
	
	// Line 249: Convert to hex string lowercase
	testpwd := strings.ToLower(hex.EncodeToString(buf[:]))
	
	fmt.Println("=== Exact C# Logic Simulation ===")
	fmt.Printf("Stored password (DB): %s
", storedPasswordInDB)
	fmt.Printf("Frontword: %d
", frontword)
	fmt.Printf("Backword: %d
", backword)
	fmt.Printf("
Line 247 - str: %s
", str)
	fmt.Printf("Line 248 - SHA1: %02x
", buf)
	fmt.Printf("Line 249 - testpwd (lowercase hex): %s
", testpwd)
	fmt.Printf("
Client sent: %s
", clientSentPassword)
	fmt.Printf("
Line 250 - Match: %v
", testpwd == clientSentPassword)
	
	if testpwd != clientSentPassword {
		fmt.Println("
❌ PASSWORD MISMATCH!")
		fmt.Println("This means the account 'dummy' in the database has password 'dummy123',")
		fmt.Println("but the client is trying to login with a DIFFERENT password.")
		fmt.Println("
Solution: Use the correct password or update the database.")
	}
}
