# Alur Login ECO — Tahap 1 hingga 4 (referensi protokol)

> Dokumen ini menjelaskan alur autentikasi & masuk-map klien `eco.exe` asli pada
> server C# (SagaValidation + SagaLogin + SagaMap), berdasarkan pembacaan kode sumber
> langsung. Dipakai sebagai acuan saat port ke Go (lihat `internal/login`, `internal/game`).
>
> Semua nomor opcode, offset, dan rumus di sini diambil dari kode C# aktual, bukan tebakan.

## Gambaran besar

Klien tidak konek ke satu server. Ada **dua koneksi TCP terpisah**:

```
                 koneksi #1 (auth)                     internal
  eco.exe ───────────────────────▶ SagaValidation ◀──────────────▶ SagaLogin
   │              :12000  (port asli; di mesin ini Validation=12000, Login=12001)
   │
   │              koneksi #2 (game)
   └────────────────────────────────────────────────────▶ SagaMap  :12002
```

- **SagaValidation** & **SagaLogin** berbagi DB akun yang sama (tabel `login`).
- **SagaMap** mendaftar ke SagaLogin saat startup lewat **INTERN packet** (opcode `0xFFF0`),
  bukan koneksi dari klien.
- Konvensi opcode: `CSMG_*` = client→server, `SSMG_*` = server→client.

---

## Tahap 0 — Pertukaran kunci enkripsi (sebelum login apa pun)

Terjadi otomatis di [`NetIO.ReceiveKeyExchange`](../../SagaLib/NetIO.cs#L192) begitu socket
tersambung, **sebelum** paket aplikasi apa pun. Ini Diffie-Hellman → AES-128.

| Langkah | Arah | Isi |
|---|---|---|
| 1 | C→S | 8 byte awal (pemicu) |
| 2 | S→C | blob **529 byte**: modulus DH 128-byte (hex, huruf kecil) @offset 13, base `0x32`, public-key server (`Two.modPow(privateKey, Module)`) hex @offset 273 |
| 3 | C→S | **260 byte**: public-key klien (256 byte hex @offset 4) |
| 4 | — | kedua sisi hitung shared secret → **kunci AES-128** |

Detail kripto ([`Encryption.cs`](../../SagaLib/Encryption.cs)):
- Modulus DH: konstanta 128-byte hardcoded (`Module`), base = `Two` (2).
- Setelah dapat 16 byte kunci, ada normalisasi nibble ([baris 51–60](../../SagaLib/Encryption.cs#L51-L60)):
  **tiap nibble > 9 dikurangi 9**. WAJIB direplikasi byte-for-byte.
- Cipher: **AES-128 ECB, tanpa padding**. Hanya region setelah offset 8 yang dienkripsi;
  2 byte SIZE paling depan tetap plaintext.

Wire frame umum: `SIZE (2 byte, plaintext) | ID (2 byte) | DATA` — ID+DATA terenkripsi.
Integer multi-byte = **big-endian**.

---

## Tahap 1 — Versi + Challenge (SagaValidation :12000)

Command table: [`ValidationClientManager.cs`](../../SagaValidation/Manager/ValidationClientManager.cs#L23-L27).

| Opcode | Paket | Handler |
|---|---|---|
| `0x0001` | `CSMG_SEND_VERSION` | `OnSendVersion` |
| `0x001F` | `CSMG_LOGIN` | `OnLogin` |
| `0x0031` | `CSMG_SERVERLET_ASK` | `OnServerLstSend` |
| `0x000A` | `CSMG_PING` | `OnPing` |
| `0x002F` | `CSMG_UNKNOWN_LIST` | `OnUnknownList` |

### 1a. Klien kirim versi → `OnSendVersion`

Klien kirim `CSMG_SEND_VERSION` ([paket](../../SagaValidation/Packets/Client/CSMG_SEND_VERSION.cs)):
6 byte versi @offset 4, dibaca sebagai string hex (mis. `03E8015F3771`).

Server membalas, di urutan ini ([`ValidationClient.cs:186`](../../SagaValidation/Network/Client/Login/ValidationClient.cs#L186)):
1. Blob 22-byte hardcoded (`FF FF E8 6A 6A CA ...`).
2. `SSMG_VERSION_ACK` (OK + echo versi).
3. **`SSMG_LOGIN_ALLOWED`** (opcode `0x001E`) berisi dua angka acak:
   ```csharp
   this.frontWord = (uint)Global.Random.Next();   // challenge
   this.backWord  = (uint)Global.Random.Next();
   p2.FrontWord = this.frontWord;   // ditulis @offset 2
   p2.BackWord  = this.backWord;    // ditulis @offset 6
   ```
   `frontWord`/`backWord` disimpan di field koneksi untuk dipakai verifikasi nanti.

**Inti:** password asli tak pernah dikirim melintasi jaringan — yang dipakai adalah
challenge-response berbasis dua angka acak ini.

---

## Tahap 2 — Login & verifikasi password (SagaValidation)

Klien kirim `CSMG_LOGIN` (opcode `0x001F`) → [`OnLogin`](../../SagaValidation/Network/Client/Login/ValidationClient.cs#L47).

### Format paket `CSMG_LOGIN`
[`CSMG_LOGIN.cs`](../../SagaValidation/Packets/Client/CSMG_LOGIN.cs): `size=55`, `offset=8`.
String dibaca **ASCII**, masing-masing diawali 1 byte panjang:
```
offset 2: [len][UserName...]
          [len][Password...]   ← "Password" di sini BUKAN password mentah (lihat bawah)
```

### Urutan pengecekan di `OnLogin`
1. Kirim `SSMG_LOGIN_ACK = OK` lebih dulu (sekadar TCP handshake-flag, sesuai komentar kode).
2. Ambil akun: `ValidationServer.accountDB.GetUser(username)`.
3. **Client-version whitelist** ([baris 63–72](../../SagaValidation/Network/Client/Login/ValidationClient.cs#L63-L72)):
   versi klien harus di whitelist, KECUALI GM (gmlevel ≥ 50) yang bypass. Dicek di sini
   (bukan saat versi dikirim) karena GMLevel baru diketahui setelah username diketahui.
4. Server-close & maintenance: kalau map server mati & user non-GM → tolak dengan pesan maintenance.
5. **Verifikasi password** → `CheckPassword`.
6. Banned → `LOGIN_ERR_BFALOCK`; password salah → `LOGIN_ERR_BADPASS`.

### Mekanisme password: SHA-1 challenge-response

Inti ada di [`MySQLAccountDB.CheckPassword`](../../SagaDB/MySQLAccountDB.cs#L230):

```csharp
// frontword & backword = challenge acak dari Tahap 1
string str = string.Format("{0}{1}{2}",
    frontword,
    ((string)result[0]["password"]).ToLower(),  // hash password tersimpan di DB
    backword);
byte[] buf = sha1.ComputeHash(Encoding.ASCII.GetBytes(str));
var testpwd = Conversions.bytes2HexString(buf).ToLower();
return password == testpwd;   // bandingkan string hex
```

**Tiga komponen:**
- **Tersimpan di DB** (tabel `login`, kolom `password`): **hash** password (bukan teks polos),
  dipakai dalam bentuk `.ToLower()`.
- **Yang dikirim klien** (`Password` di paket): BUKAN password user, melainkan
  hasil klien menghitung sendiri:
  ```
  testpwd = SHA1( frontWord + hash_password_dari_DB + backWord )   // string hex huruf kecil
  ```
- **Verifikasi server**: hitung rumus identik pakai hash dari DB-nya + challenge yang dia simpan,
  lalu bandingkan string hex.

### Kenapa bisa login

Login sukses bila **tiga hal sinkron**:
1. **Challenge sama** — server simpan `frontWord`/`backWord`, klien pakai angka identik yang baru diterima.
2. **Hash password di DB sama** dengan hash yang dipakai klien.
3. **Algoritma & urutan gabungan string sama** persis: `SHA1(front + passhash + back)`.

Karena challenge diacak tiap koneksi, hasil SHA-1 selalu berbeda → **replay attack tidak berguna**.
Inilah sebabnya password "bisa login" walau tak pernah dikirim telanjang.
Di log: `Player:ADMIN logged in.` = akun ADMIN ada di tabel `login` dan hash-nya cocok.

### Catatan keamanan untuk port Go
Algoritma wire ini **SHA-1 + hash lama** — lemah menurut standar sekarang, tetapi
**klien `eco.exe` asli melakukan perhitungan ini secara hardcoded di sisinya.** Maka saat
port ke Go, rumus `SHA1(front + passhash + back)` **wajib direplikasi** agar klien asli bisa login.
bcrypt (rencana skema baru) hanya bisa jadi lapisan penyimpanan tambahan di server — tidak bisa
menggantikan protokol wire yang klien harapkan. (Catat untuk Plan 4 Login.)

---

## Tahap 3 — Daftar server & pilih karakter (SagaLogin :12001)

### 3a. Daftar server (masih lewat koneksi Validation)
Klien kirim `CSMG_SERVERLET_ASK` (opcode `0x0031`) → `OnServerLstSend`
([`ValidationClient.cs:209`](../../SagaValidation/Network/Client/Login/ValidationClient.cs#L209)):
- `SSMG_SERVER_LST_START` → `SSMG_SERVER_LST_SEND` (nama server + IP, format
  `"T"+IP+","+IP+","+IP+","+IP`) → `SSMG_SERVER_LST_END`.
- **Guard penting:** request ke-2 pada socket yang sama = **disconnect paksa**
  ([baris 218–222](../../SagaValidation/Network/Client/Login/ValidationClient.cs#L218-L222)).
  Ini memaksa klien membuka koneksi validation baru & mengulang handshake, supaya
  server-select terisi (bukan kosong) setelah logout.

### 3b. Pilih karakter (koneksi ke SagaLogin :12001)
Command table login: [`LoginClientManager.cs:44-69`](../../SagaLogin/Manager/LoginClientManager.cs#L44-L69).

| Opcode | Paket | Fungsi |
|---|---|---|
| `0x002A` | `CSMG_CHAR_STATUS` | minta status/daftar karakter |
| `0x00A0` | `CSMG_CHAR_CREATE` | buat karakter |
| `0x00A5` | `CSMG_CHAR_DELETE` | hapus karakter |
| `0x00A7` | `CSMG_CHAR_SELECT` | pilih karakter |
| `0x0032` | `CSMG_REQUEST_MAP_SERVER` | minta alamat map server |
| `0xFFF0` | `INTERN_LOGIN_REGISTER` | (internal, dari Map) daftar map |

- `OnCharStatus` ([`LoginClient.Login.cs:353`](../../SagaLogin/Network/Client/LoginClient.Login.cs#L353)):
  kirim `SSMG_CHAR_STATUS`, friend list, gifts, mails.
- `SendCharData`: kirim `SSMG_CHAR_DATA` (daftar karakter) + `SSMG_CHAR_EQUIP` (penampilan/equip).

### 3c. Request map server → handoff
`CSMG_REQUEST_MAP_SERVER` (opcode `0x0032`, bawa `Slot`) →
[`OnRequestMapServer`](../../SagaLogin/Network/Client/LoginClient.Login.cs#L322):

```csharp
// cari map server yang meng-host map tempat karakter berada
if (MapServerManager.Instance.MapServers.ContainsKey(selectedChar.MapID)) {
    p1.ServerID = 1; p1.IP = server.IP; p1.Port = server.port;
}
// fallback: coba mapID dibulatkan ke kelipatan 1000
// gagal total: ServerID = 255 (error)
this.netIO.SendPacket(p1);   // SSMG_SEND_TO_MAP_SERVER → kasih IP:port map ke klien
```

Map server mana yang meng-host map apa diketahui dari registrasi `INTERN_LOGIN_REGISTER`
([`LoginClient.Map.cs:31`](../../SagaLogin/Network/Client/LoginClient.Map.cs#L31)): saat startup,
SagaMap mengirim password + IP + port + daftar mapID yang dihost; SagaLogin memverifikasi
password lalu mengisi `MapServerManager.MapServers[mapID] = server`.

---

## Tahap 4 — Masuk Map (SagaMap :12002)

1. Klien buka **koneksi TCP kedua** ke IP:port dari `SSMG_SEND_TO_MAP_SERVER`.
   Handshake kripto Tahap 0 **diulang** di koneksi baru ini.
2. Klien identifikasi diri; SagaMap memvalidasi sesi terhadap data yang sudah didaftarkan
   SagaLogin, lalu **load karakter dari DB** (di log: `Loading player(1): ADMIN item data... size: 15948`).
3. SagaMap **spawn** karakter, kirim data map + posisi + stat + equip-look.
4. Player aktif → log `Player:ADMIN logged in.` lalu `Online Player:1`.

Pada port Go, INTERN packet (Tahap 3c + validasi sesi Tahap 4) digantikan **Registry pusat
in-memory + token handoff sekali-pakai**, karena ketiga server jadi satu proses.

---

## Ringkasan opcode (acuan cepat)

| Tahap | Opcode | Nama | Arah |
|---|---|---|---|
| 1 | `0x0001` | CSMG_SEND_VERSION | C→S |
| 1 | `0x001E` | SSMG_LOGIN_ALLOWED (frontWord/backWord) | S→C |
| 2 | `0x001F` | CSMG_LOGIN | C→S |
| 3a | `0x0031` | CSMG_SERVERLET_ASK | C→S |
| 3a | `0x0033` | SSMG_SERVER_LST_SEND | S→C |
| 3b | `0x002A` | CSMG_CHAR_STATUS | C→S |
| 3b | `0x00A0` | CSMG_CHAR_CREATE | C→S |
| 3b | `0x00A5` | CSMG_CHAR_DELETE | C→S |
| 3b | `0x00A7` | CSMG_CHAR_SELECT | C→S |
| 3c | `0x0032` | CSMG_REQUEST_MAP_SERVER | C→S |
| 3c | `0xFFF0` | INTERN_LOGIN_REGISTER (Map→Login) | internal |
| semua | `0x000A` | CSMG_PING | C→S |
