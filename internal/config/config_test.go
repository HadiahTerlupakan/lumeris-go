package config

import "testing"

func TestLoadDefaults(t *testing.T) {
	t.Setenv("LUMERIS_DB_DSN", "")
	t.Setenv("LUMERIS_PORT_VALIDATION", "")
	t.Setenv("LUMERIS_PORT_LOGIN", "")
	t.Setenv("LUMERIS_PORT_MAP", "")
	t.Setenv("LUMERIS_PUBLIC_IP", "")
	t.Setenv("LUMERIS_CLIENT_ENCODING", "")

	c := Load()

	if c.PortValidation != 12022 {
		t.Errorf("PortValidation = %d, mau 12022", c.PortValidation)
	}
	if c.PortLogin != 12023 {
		t.Errorf("PortLogin = %d, mau 12023", c.PortLogin)
	}
	if c.PortMap != 12024 {
		t.Errorf("PortMap = %d, mau 12024", c.PortMap)
	}
	if c.PublicIP != "127.0.0.1" {
		t.Errorf("PublicIP = %q, mau 127.0.0.1", c.PublicIP)
	}
	if c.ClientEncoding != "Shift_JIS" {
		t.Errorf("ClientEncoding = %q, mau Shift_JIS", c.ClientEncoding)
	}
}

func TestLoadOverride(t *testing.T) {
	t.Setenv("LUMERIS_PORT_MAP", "13024")
	t.Setenv("LUMERIS_PUBLIC_IP", "10.0.0.5")
	t.Setenv("LUMERIS_DB_DSN", "postgres://u:p@db:5432/lumeris")

	c := Load()

	if c.PortMap != 13024 {
		t.Errorf("PortMap = %d, mau 13024", c.PortMap)
	}
	if c.PublicIP != "10.0.0.5" {
		t.Errorf("PublicIP = %q, mau 10.0.0.5", c.PublicIP)
	}
	if c.DBDSN != "postgres://u:p@db:5432/lumeris" {
		t.Errorf("DBDSN = %q salah", c.DBDSN)
	}
}
