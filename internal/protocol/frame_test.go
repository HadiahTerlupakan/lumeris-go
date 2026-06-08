package protocol

import (
	"bytes"
	"testing"
)

func TestDecodeFrameSingleSubMessage(t *testing.T) {
	c := NewCrypto()
	c.aesKey = []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}

	// Sub-message: ID=0x0001, data="AB" (2 byte) => isi = 00 01 41 42 (4 byte).
	// Prefix len 2-byte BE = panjang (ID+data) = 4 => 00 04.
	// Region (pra-pad) = 00 04 00 01 41 42 (6 byte). INNER M = 6.
	// Region di-pad ke kelipatan 16 (selalu +mod): 6 -> +10 = 16 byte.
	sub := []byte{0x00, 0x04, 0x00, 0x01, 0x41, 0x42}
	region := make([]byte, 16)
	copy(region, sub)

	// Bangun frame: [OUTER 4][INNER 4][region terenkripsi].
	frame := make([]byte, 8+len(region))
	// INNER M (byte 4-7) = 6 (panjang sub-message valid, pra-pad)
	frame[4], frame[5], frame[6], frame[7] = 0x00, 0x00, 0x00, 0x06
	// region terenkripsi mulai byte 8
	enc := c.Encrypt(append(make([]byte, 8), region...), 8)
	copy(frame[8:], enc[8:])
	// OUTER N (byte 0-3) = len region = 16
	frame[0], frame[1], frame[2], frame[3] = 0x00, 0x00, 0x00, 0x10

	subs, err := DecodeFrame(c, frame)
	if err != nil {
		t.Fatalf("DecodeFrame error: %v", err)
	}
	if len(subs) != 1 {
		t.Fatalf("jumlah sub-message = %d, mau 1", len(subs))
	}
	if subs[0].ID != 0x0001 {
		t.Errorf("ID = %#x, mau 0x0001", subs[0].ID)
	}
	if !bytes.Equal(subs[0].Data, []byte{0x41, 0x42}) {
		t.Errorf("Data = %v, mau [41 42]", subs[0].Data)
	}
}
