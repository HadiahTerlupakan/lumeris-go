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
	// Known data
	password := "dummy123" // Password yang kita tahu ada di DB
	front := uint32(0x4bb6b365)
	back := uint32(0xd9a2302c)
	targetSHA1 := "cd18578fd3f1d3f187efab55c905507e9331255f"
	
	h := md5.Sum([]byte(password))
	md5Hex := hex.EncodeToString(h[:])
	md5Bytes, _ := hex.DecodeString(md5Hex)
	
	fmt.Println("=== Testing Different Challenge Formats ===")
	fmt.Printf("Password: '%s'
", password)
	fmt.Printf("MD5: %s
", md5Hex)
	fmt.Printf("Target SHA1: %s

", targetSHA1)
	
	// Test 1: Front + MD5_uppercase + Back (current implementation)
	buf1 := make([]byte, 4+32+4)
	binary.BigEndian.PutUint32(buf1[0:4], front)
	copy(buf1[4:36], []byte(strings.ToUpper(md5Hex)))
	binary.BigEndian.PutUint32(buf1[36:40], back)
	sha1_1 := sha1.Sum(buf1)
	fmt.Printf("1. Front(BE) + MD5_upper + Back(BE): %s %v
", 
		hex.EncodeToString(sha1_1[:]), hex.EncodeToString(sha1_1[:]) == targetSHA1)
	
	// Test 2: Front + MD5_lowercase + Back
	buf2 := make([]byte, 4+32+4)
	binary.BigEndian.PutUint32(buf2[0:4], front)
	copy(buf2[4:36], []byte(strings.ToLower(md5Hex)))
	binary.BigEndian.PutUint32(buf2[36:40], back)
	sha1_2 := sha1.Sum(buf2)
	fmt.Printf("2. Front(BE) + MD5_lower + Back(BE): %s %v
", 
		hex.EncodeToString(sha1_2[:]), hex.EncodeToString(sha1_2[:]) == targetSHA1)
	
	// Test 3: Front(LE) + MD5_upper + Back(LE)
	buf3 := make([]byte, 4+32+4)
	binary.LittleEndian.PutUint32(buf3[0:4], front)
	copy(buf3[4:36], []byte(strings.ToUpper(md5Hex)))
	binary.LittleEndian.PutUint32(buf3[36:40], back)
	sha1_3 := sha1.Sum(buf3)
	fmt.Printf("3. Front(LE) + MD5_upper + Back(LE): %s %v
", 
		hex.EncodeToString(sha1_3[:]), hex.EncodeToString(sha1_3[:]) == targetSHA1)
	
	// Test 4: Front + MD5_raw_bytes + Back
	buf4 := make([]byte, 4+16+4)
	binary.BigEndian.PutUint32(buf4[0:4], front)
	copy(buf4[4:20], md5Bytes)
	binary.BigEndian.PutUint32(buf4[20:24], back)
	sha1_4 := sha1.Sum(buf4)
	fmt.Printf("4. Front(BE) + MD5_raw + Back(BE): %s %v
", 
		hex.EncodeToString(sha1_4[:]), hex.EncodeToString(sha1_4[:]) == targetSHA1)
	
	// Test 5: MD5 + Front + Back
	buf5 := make([]byte, 32+4+4)
	copy(buf5[0:32], []byte(strings.ToUpper(md5Hex)))
	binary.BigEndian.PutUint32(buf5[32:36], front)
	binary.BigEndian.PutUint32(buf5[36:40], back)
	sha1_5 := sha1.Sum(buf5)
	fmt.Printf("5. MD5_upper + Front(BE) + Back(BE): %s %v
", 
		hex.EncodeToString(sha1_5[:]), hex.EncodeToString(sha1_5[:]) == targetSHA1)
	
	// Test 6: Back + MD5 + Front (reversed)
	buf6 := make([]byte, 4+32+4)
	binary.BigEndian.PutUint32(buf6[0:4], back)
	copy(buf6[4:36], []byte(strings.ToUpper(md5Hex)))
	binary.BigEndian.PutUint32(buf6[36:40], front)
	sha1_6 := sha1.Sum(buf6)
	fmt.Printf("6. Back(BE) + MD5_upper + Front(BE): %s %v
", 
		hex.EncodeToString(sha1_6[:]), hex.EncodeToString(sha1_6[:]) == targetSHA1)
	
	// Test 7: Front + Back + MD5
	buf7 := make([]byte, 4+4+32)
	binary.BigEndian.PutUint32(buf7[0:4], front)
	binary.BigEndian.PutUint32(buf7[4:8], back)
	copy(buf7[8:40], []byte(strings.ToUpper(md5Hex)))
	sha1_7 := sha1.Sum(buf7)
	fmt.Printf("7. Front(BE) + Back(BE) + MD5_upper: %s %v
", 
		hex.EncodeToString(sha1_7[:]), hex.EncodeToString(sha1_7[:]) == targetSHA1)
	
	// Test 8: Only MD5
	buf8 := []byte(strings.ToUpper(md5Hex))
	sha1_8 := sha1.Sum(buf8)
	fmt.Printf("8. MD5_upper only: %s %v
", 
		hex.EncodeToString(sha1_8[:]), hex.EncodeToString(sha1_8[:]) == targetSHA1)
	
	fmt.Println("
If none match, the client is using a different password than 'dummy123'")
}
