package protocol

import (
	"encoding/binary"
	"errors"
)

// SubMessage adalah satu pesan aplikasi di dalam frame: ID opcode + data payload.
type SubMessage struct {
	ID   uint16
	Data []byte
}

// firstLevelLen = lebar prefix panjang sub-message (2 byte untuk login & map ECO).
const firstLevelLen = 2

// maxSubMessages membatasi jumlah sub-message per frame (guard anti-runaway).
const maxSubMessages = 1024

// DecodeFrame mendekripsi region (dari offset 8) lalu memisahkan sub-message.
// frame = [OUTER 4][INNER 4][region terenkripsi]. Mengembalikan daftar sub-message.
func DecodeFrame(c *Crypto, frame []byte) ([]SubMessage, error) {
	if len(frame) < 8 {
		return nil, errors.New("frame < 8 byte")
	}
	dec := c.Decrypt(frame, 8)
	inner := int(binary.BigEndian.Uint32(dec[4:8])) // INNER M
	if inner < 0 || 8+inner > len(dec) {
		return nil, errors.New("INNER length di luar batas frame")
	}
	var subs []SubMessage
	off := 0
	for off < inner {
		if len(subs) >= maxSubMessages {
			return nil, errors.New("melebihi batas sub-message")
		}
		if off+firstLevelLen > inner {
			return nil, errors.New("prefix sub-message terpotong")
		}
		size := int(binary.BigEndian.Uint16(dec[8+off:]))
		off += firstLevelLen
		if size < 2 || off+size > inner {
			return nil, errors.New("ukuran sub-message di luar batas")
		}
		id := binary.BigEndian.Uint16(dec[8+off:])
		data := make([]byte, size-2)
		copy(data, dec[8+off+2:8+off+size])
		subs = append(subs, SubMessage{ID: id, Data: data})
		off += size
	}
	return subs, nil
}

// EncodeFrame membangun frame wire lengkap dari satu sub-message (ID+data),
// lalu mengenkripsi region dari offset 8. Layout hasil:
// [OUTER 4 BE][INNER 4 BE][ region: (len2|ID2|data) + padding-nol-ke-16 ].
func EncodeFrame(c *Crypto, id uint16, data []byte) []byte {
	// sub-message: [len 2-byte BE = 2+len(data)][ID 2-byte][data]
	subLen := 2 + len(data)
	if subLen > 0xFFFF {
		panic("EncodeFrame: sub-message terlalu besar (len data melebihi 65533)")
	}
	region := make([]byte, firstLevelLen+subLen)
	binary.BigEndian.PutUint16(region[0:], uint16(subLen))
	binary.BigEndian.PutUint16(region[firstLevelLen:], id)
	copy(region[firstLevelLen+2:], data)

	inner := len(region) // INNER M = panjang sub-message valid (pra-pad)

	// padding ke kelipatan 16 (selalu tambah; mod tak pernah 0) — replika NetIO.cs:684.
	mod := 16 - (len(region) % 16)
	region = append(region, make([]byte, mod)...)

	// frame: 8 byte header + region
	frame := make([]byte, 8+len(region))
	copy(frame[8:], region)
	binary.BigEndian.PutUint32(frame[4:], uint32(inner))       // INNER M
	binary.BigEndian.PutUint32(frame[0:], uint32(len(region))) // OUTER N = len region (pasca-pad)

	return c.Encrypt(frame, 8)
}
