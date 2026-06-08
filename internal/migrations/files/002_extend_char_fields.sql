-- Migration 002: Extend accounts (deletepass) & characters (race, gender, form, wig, face, quest, job levels, rebirth)
-- Untuk Plan 4 login flow: char-list packet butuh field tambahan

-- Accounts: deletepass untuk char delete
ALTER TABLE accounts ADD COLUMN IF NOT EXISTS deletepass text NOT NULL DEFAULT '0000';

-- Characters: field appearance & progression tambahan
ALTER TABLE characters ADD COLUMN IF NOT EXISTS race smallint NOT NULL DEFAULT 0;
ALTER TABLE characters ADD COLUMN IF NOT EXISTS gender smallint NOT NULL DEFAULT 0;
ALTER TABLE characters ADD COLUMN IF NOT EXISTS form smallint NOT NULL DEFAULT 0;
ALTER TABLE characters ADD COLUMN IF NOT EXISTS wig smallint NOT NULL DEFAULT 255;
ALTER TABLE characters ADD COLUMN IF NOT EXISTS face_id int NOT NULL DEFAULT 0;
ALTER TABLE characters ADD COLUMN IF NOT EXISTS quest_remaining int NOT NULL DEFAULT 3;
ALTER TABLE characters ADD COLUMN IF NOT EXISTS job_level_1 int NOT NULL DEFAULT 1;
ALTER TABLE characters ADD COLUMN IF NOT EXISTS job_level_2x int NOT NULL DEFAULT 0;
ALTER TABLE characters ADD COLUMN IF NOT EXISTS job_level_2t int NOT NULL DEFAULT 0;
ALTER TABLE characters ADD COLUMN IF NOT EXISTS job_level_3 int NOT NULL DEFAULT 0;
ALTER TABLE characters ADD COLUMN IF NOT EXISTS rebirth boolean NOT NULL DEFAULT false;
