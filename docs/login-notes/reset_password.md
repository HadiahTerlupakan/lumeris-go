# Password Debugging

## Masalah:
Client terus mengirim SHA1 yang **TIDAK COCOK** dengan password `test123`

## Yang Sudah Dicoba:
- Formula challenge: ✅ BENAR
- Pernah sukses login (17:09:39): ✅ YA
- Test ulang dengan client fresh: ❌ GAGAL TERUS

## Kemungkinan:
1. Password yang Anda ketik di client **BUKAN** `test123`
2. Client cache password lain
3. Ada masalah dengan keyboard/input

## Solusi Debug:

### Opsi 1: Pastikan Password yang Diketik
**Pertanyaan:** Password apa PERSIS yang Anda ketik di client?
- `test123` (lowercase)?
- `Test123` (capital T)?  
- `TEST123` (uppercase)?
- Atau password lain?

### Opsi 2: Ganti Password Simple
Saya bisa update password dummy2 ke password super simple untuk test:
```sql
UPDATE accounts SET password_hash = '81dc9bdb52d04dc20036dbd8313ed055' WHERE username = 'dummy2';
-- MD5('1234') = 81dc9bdb52d04dc20036dbd8313ed055
```

Lalu coba login dengan password `1234`

### Opsi 3: Buat Account Baru
Register account baru dengan password yang Anda mau:
```bash
curl -X POST http://localhost:8001/register \
  -H "username: testlogin" \
  -H "password: yourpassword"
```

**Tolong kasih tahu: password apa yang sebenarnya Anda ketik di client?**
