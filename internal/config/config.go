package config

import (
	"os"
	"strconv"
)

// Config menampung seluruh konfigurasi server yang dibaca dari environment.
type Config struct {
	DBDSN          string
	PortValidation int
	PortLogin      int
	PortMap        int
	PublicIP       string
	ClientEncoding string
}

// Load membaca konfigurasi dari environment variable, memakai default bila kosong.
func Load() Config {
	return Config{
		DBDSN:          envStr("LUMERIS_DB_DSN", "postgres://lumeris:lumeris@localhost:5432/lumeris?sslmode=disable"),
		PortValidation: envInt("LUMERIS_PORT_VALIDATION", 12022),
		PortLogin:      envInt("LUMERIS_PORT_LOGIN", 12023),
		PortMap:        envInt("LUMERIS_PORT_MAP", 12024),
		PublicIP:       envStr("LUMERIS_PUBLIC_IP", "127.0.0.1"),
		ClientEncoding: envStr("LUMERIS_CLIENT_ENCODING", "Shift_JIS"),
	}
}

func envStr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}
