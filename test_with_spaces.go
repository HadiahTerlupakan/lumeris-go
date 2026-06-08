package main
import (
	"crypto/sha1"
	"fmt"
)

func main() {
	front := uint32(1950729824)
	back := uint32(2749064412)
	md5Hash := "57b2f4c72fd9e904593453cfed3ef751"
	targetSHA1 := "9b6bff95eef22dde49f7814681c883e0bae6f00a"
	
	fmt.Println("=== TEST WITH SPACES AND DIFFERENT SEPARATORS ===\n")
	
	tests := []struct{
		name string
		str  string
	}{
		{"front + md5 + back (no separator)", fmt.Sprintf("%d%s%d", front, md5Hash, back)},
		{"front + ' ' + md5 + ' ' + back", fmt.Sprintf("%d %s %d", front, md5Hash, back)},
		{"front + ',' + md5 + ',' + back", fmt.Sprintf("%d,%s,%d", front, md5Hash, back)},
		{"front + '-' + md5 + '-' + back", fmt.Sprintf("%d-%s-%d", front, md5Hash, back)},
		{"front + '_' + md5 + '_' + back", fmt.Sprintf("%d_%s_%d", front, md5Hash, back)},
		{"front + ':' + md5 + ':' + back", fmt.Sprintf("%d:%s:%d", front, md5Hash, back)},
		{"front + '|' + md5 + '|' + back", fmt.Sprintf("%d|%s|%d", front, md5Hash, back)},
	}
	
	for _, test := range tests {
		hash := fmt.Sprintf("%x", sha1.Sum([]byte(test.str)))
		if hash == targetSHA1 {
			fmt.Printf("✅ MATCH! %s\n", test.name)
			fmt.Printf("   String: %s\n", test.str)
			fmt.Printf("   SHA1:   %s\n", hash)
			return
		}
	}
	
	fmt.Println("❌ No match with separators either!\n")
	fmt.Println("Let me re-check C# source code more carefully...")
}
