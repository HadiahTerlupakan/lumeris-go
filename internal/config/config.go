package config

import (
	"fmt"
	"os"
	"strconv"
)

// Config menampung seluruh konfigurasi server yang dibaca dari environment.
type Config struct {
	DBDSN            string
	PortValidation   int
	PortLogin        int
	PortMap          int
	PortHTTP         string // Port untuk HTTP register (:8001)
	ListenValidation string // Computed: 0.0.0.0:PortValidation
	ListenLogin      string // Computed: 0.0.0.0:PortLogin
	ListenMap        string // Computed: 0.0.0.0:PortMap
	PublicIP         string
	ClientEncoding   string
	ServerName       string
	DevMode          bool   // Development mode: bypass password check
}

// Load membaca konfigurasi dari environment variable, memakai default bila kosong.
func Load() Config {
	portValidation := envInt("LUMERIS_PORT_VALIDATION", 12022)
	portLogin := envInt("LUMERIS_PORT_LOGIN", 12023)
	portMap := envInt("LUMERIS_PORT_MAP", 12024)
	portHTTP := envInt("LUMERIS_PORT_HTTP", 8001)
	devMode := envStr("LUMERIS_DEV_MODE", "false") == "true" // Default false: jangan sembunyikan bug password

	return Config{
		DBDSN:            envStr("LUMERIS_DB_DSN", "postgres://lumeris:lumeris@localhost:5432/lumeris?sslmode=disable"),
		PortValidation:   portValidation,
		PortLogin:        portLogin,
		PortMap:          portMap,
		PortHTTP:         fmt.Sprintf(":%d", portHTTP),
		ListenValidation: fmt.Sprintf("0.0.0.0:%d", portValidation),
		ListenLogin:      fmt.Sprintf("0.0.0.0:%d", portLogin),
		ListenMap:        fmt.Sprintf("0.0.0.0:%d", portMap),
		PublicIP:         envStr("LUMERIS_PUBLIC_IP", "127.0.0.1"),
		ClientEncoding:   envStr("LUMERIS_CLIENT_ENCODING", "Shift_JIS"),
		ServerName:       envStr("LUMERIS_SERVER_NAME", "SagaECO"),
		DevMode:          devMode,
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
