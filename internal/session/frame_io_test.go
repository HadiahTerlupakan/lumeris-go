package session

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"

	"lumeris-go/internal/protocol"
)

// readyDHPair menjalankan DH Go-ke-Go nyata dan mengembalikan dua Crypto yang
// AES key-nya sudah siap & identik (simetri DH diverifikasi di Plan 2A).
func readyDHPair() (server, client *protocol.Crypto) {
	server = protocol.NewCrypto()
	server.MakePrivateKey()
	client = protocol.NewCrypto()
	client.MakePrivateKey()
	server.MakeAESKeyHex(strings.ToUpper(hex.EncodeToString(client.GetKeyExchangeBytes())))
	client.MakeAESKeyHex(strings.ToUpper(hex.EncodeToString(server.GetKeyExchangeBytes())))
	return server, client
}

func TestReadFrameRoundTrip(t *testing.T) {
	c, _ := readyDHPair()
	frame := protocol.EncodeFrame(c, 0x001E, []byte("MXMI"))

	subs, err := ReadFrame(bytes.NewReader(frame), c)
	if err != nil {
		t.Fatalf("ReadFrame error: %v", err)
	}
	if len(subs) != 1 {
		t.Fatalf("jumlah sub = %d, mau 1", len(subs))
	}
	if subs[0].ID != 0x001E {
		t.Errorf("ID = %#x, mau 0x001E", subs[0].ID)
	}
	if !bytes.Equal(subs[0].Data, []byte("MXMI")) {
		t.Errorf("Data = %q, mau MXMI", subs[0].Data)
	}
}

func TestReadFrameRejectsOversizeOuter(t *testing.T) {
	c, _ := readyDHPair()
	// OUTER = 2_000_000 (> batas 1024000) → harus error sebelum alokasi region.
	bad := []byte{0x00, 0x1E, 0x84, 0x80} // BE 2_000_000
	_, err := ReadFrame(bytes.NewReader(bad), c)
	if err == nil {
		t.Fatal("ReadFrame menerima OUTER di luar batas; mau error")
	}
}
