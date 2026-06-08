package main
import (
	"crypto/sha1"
	"encoding/binary"
	"fmt"
)

func main() {
	// Data dari log attempt 1
	packetHex := []byte{0x00, 0x00, 0xff, 0xbf, 0x29, 0x64, 0xeb, 0x40, 0x60, 0x82}
	expectedFront := uint32(4290718052)
	expectedBack := uint32(3946864770)
	clientSHA1 := "f791f5922b74dab0ad27cf36b2cf9e36c7a42502"
	storedMD5 := "57b2f4c72fd9e904593453cfed3ef751"
	
	fmt.Println("=== Analyzing LOGIN_ALLOWED packet ===")
	fmt.Printf("Packet hex: %02x\n", packetHex)
	fmt.Printf("Expected front: %d (0x%08x)\n", expectedFront, expectedFront)
	fmt.Printf("Expected back: %d (0x%08x)\n\n", expectedBack, expectedBack)
	
	// Test different interpretations
	fmt.Println("=== Testing different byte interpretations ===")
	
	// 1. Big-endian from offset 2 (our current method)
	front1 := binary.BigEndian.Uint32(packetHex[2:6])
	back1 := binary.BigEndian.Uint32(packetHex[6:10])
	fmt.Printf("1. BE offset 2,6: front=%d, back=%d\n", front1, back1)
	testChallenge(front1, back1, storedMD5, clientSHA1)
	
	// 2. Little-endian from offset 2
	front2 := binary.LittleEndian.Uint32(packetHex[2:6])
	back2 := binary.LittleEndian.Uint32(packetHex[6:10])
	fmt.Printf("2. LE offset 2,6: front=%d, back=%d\n", front2, back2)
	testChallenge(front2, back2, storedMD5, clientSHA1)
	
	// 3. Big-endian from offset 0
	front3 := binary.BigEndian.Uint32(packetHex[0:4])
	back3 := binary.BigEndian.Uint32(packetHex[4:8])
	fmt.Printf("3. BE offset 0,4: front=%d, back=%d\n", front3, back3)
	testChallenge(front3, back3, storedMD5, clientSHA1)
	
	// 4. Little-endian from offset 0
	front4 := binary.LittleEndian.Uint32(packetHex[0:4])
	back4 := binary.LittleEndian.Uint32(packetHex[4:8])
	fmt.Printf("4. LE offset 0,4: front=%d, back=%d\n", front4, back4)
	testChallenge(front4, back4, storedMD5, clientSHA1)
}

func testChallenge(front, back uint32, md5Hex, expectedSHA1 string) {
	str := fmt.Sprintf("%d%s%d", front, md5Hex, back)
	sha := sha1.Sum([]byte(str))
	shaHex := fmt.Sprintf("%x", sha)
	
	if shaHex == expectedSHA1 {
		fmt.Printf("   ✓✓✓ MATCH! Challenge: %s\n", str)
	}
}
