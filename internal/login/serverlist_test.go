package login

import (
	"bytes"
	"testing"
)

// TestBuildServerListSend memverifikasi struktur byte body SSMG_SERVER_LST_SEND
// cocok dengan C# SagaValidation SSMG_SERVER_LST_SEND.cs.
//
// Di C#: data[0-1] = ID (0x33), data[2] = nameLen, data[3..] = name+\0, lalu ipLen, ip+\0.
// EncodeFrame Go menambahkan ID secara TERPISAH ([subLen][ID][body]), jadi body yang
// di-pass ke s.Send TIDAK boleh menyertakan ID maupun padding apa pun:
//
//	body = [nameLen 1][name + \0][ipLen 1][ip + \0]
//
// nameLen & ipLen termasuk byte \0 (sesuai PutByte((byte)buf.Length,...) di C#,
// dengan buf = Unicode.GetBytes(value + "\0")).
func TestBuildServerListSend(t *testing.T) {
	name := "SagaECO"
	ip := "T127.0.0.1,127.0.0.1,127.0.0.1,127.0.0.1"

	body := BuildServerListSend(name, ip)

	// Susun ekspektasi byte-exact.
	nameBytes := append([]byte(name), 0)
	ipBytes := append([]byte(ip), 0)
	var want bytes.Buffer
	want.WriteByte(byte(len(nameBytes))) // nameLen (termasuk \0)
	want.Write(nameBytes)
	want.WriteByte(byte(len(ipBytes))) // ipLen (termasuk \0)
	want.Write(ipBytes)

	if !bytes.Equal(body, want.Bytes()) {
		t.Fatalf("server list body tidak byte-exact:\n got = %02x\nwant = %02x", body, want.Bytes())
	}

	// Cek eksplisit: byte pertama HARUS nameLen, bukan padding nol.
	if body[0] != byte(len(nameBytes)) {
		t.Errorf("byte[0] = %d, harus nameLen %d (tidak boleh ada padding di depan)", body[0], len(nameBytes))
	}
}
