package session

import (
	"encoding/binary"
	"fmt"
	"io"

	"lumeris-go/internal/protocol"
)

// maxRegion membatasi panjang region (OUTER) sejalan batas length C# (NetIO.cs:528),
// jauh di bawah cap 64MB CLAUDE.md — guard anti-alokasi-raksasa dari size attacker.
const maxRegion = 1024000

// ReadFrame membaca satu frame wire dari r: 4 byte OUTER (BE = panjang region),
// lalu (INNER 4 + region N) byte. Merakit buffer [0000][INNER][region] dan
// memanggil protocol.DecodeFrame (yang mengabaikan OUTER, memakai INNER di [4:8]).
func ReadFrame(r io.Reader, c *protocol.Crypto) ([]protocol.SubMessage, error) {
	var head [4]byte
	if _, err := io.ReadFull(r, head[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(head[:]) // OUTER = panjang region
	if n == 0 || n > maxRegion {
		return nil, fmt.Errorf("OUTER length %d di luar batas (1..%d)", n, maxRegion)
	}
	rest := make([]byte, int(n)+4) // [INNER 4][region n]
	if _, err := io.ReadFull(r, rest); err != nil {
		return nil, err
	}
	frame := make([]byte, 8+int(n))
	copy(frame[4:], rest) // frame[0:4]=0 (OUTER diabaikan DecodeFrame)
	return protocol.DecodeFrame(c, frame)
}
