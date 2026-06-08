-- Migration 003: Rename tables to match C# SagaECO schema
-- C# uses table 'login' with column 'password' (not 'accounts' with 'password_hash')

-- Rename accounts table to login
ALTER TABLE accounts RENAME TO login;

-- Rename columns to match C# schema
ALTER TABLE login RENAME COLUMN id TO account_id;
ALTER TABLE login RENAME COLUMN password_hash TO password;
ALTER TABLE login RENAME COLUMN gm_level TO gmlevel;

-- Add missing C# columns (with defaults)
ALTER TABLE login ADD COLUMN IF NOT EXISTS deletepass varchar(32) DEFAULT '0000';
ALTER TABLE login ADD COLUMN IF NOT EXISTS bank int DEFAULT 0;
ALTER TABLE login ADD COLUMN IF NOT EXISTS vshop_points int DEFAULT 0;
ALTER TABLE login ADD COLUMN IF NOT EXISTS used_vshop_points int DEFAULT 0;
ALTER TABLE login ADD COLUMN IF NOT EXISTS lastip varchar(20);
ALTER TABLE login ADD COLUMN IF NOT EXISTS questresettime timestamptz DEFAULT '2000-01-01 00:00:00';
ALTER TABLE login ADD COLUMN IF NOT EXISTS lastlogintime timestamptz DEFAULT '2000-01-01 00:00:00';
ALTER TABLE login ADD COLUMN IF NOT EXISTS macaddress varchar(15) DEFAULT '';
ALTER TABLE login ADD COLUMN IF NOT EXISTS playernames varchar(50) DEFAULT '';

-- Update characters foreign key to reference login(account_id)
ALTER TABLE characters DROP CONSTRAINT IF EXISTS characters_account_id_fkey;
ALTER TABLE characters ADD CONSTRAINT characters_account_id_fkey
    FOREIGN KEY (account_id) REFERENCES login(account_id);

-- Create index for username lookup (performance)
CREATE INDEX IF NOT EXISTS idx_login_username ON login(username);
