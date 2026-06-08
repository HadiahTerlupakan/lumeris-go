CREATE TABLE IF NOT EXISTS schema_migrations (
    version     int          PRIMARY KEY,
    applied_at  timestamptz  NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS accounts (
    id            bigserial    PRIMARY KEY,
    username      text         UNIQUE NOT NULL,
    password_hash text         NOT NULL,
    gm_level      int          NOT NULL DEFAULT 0,
    banned        bool         NOT NULL DEFAULT false,
    created_at    timestamptz  NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS characters (
    id          bigserial   PRIMARY KEY,
    account_id  bigint      NOT NULL REFERENCES accounts(id),
    slot        int         NOT NULL,
    name        text        UNIQUE NOT NULL,
    job         int         NOT NULL,
    level       int         NOT NULL DEFAULT 1,
    map_id      int         NOT NULL,
    x           int         NOT NULL,
    y           int         NOT NULL,
    hp          int         NOT NULL,
    maxhp       int         NOT NULL,
    sp          int         NOT NULL,
    maxsp       int         NOT NULL,
    str         int,
    dex         int,
    int_        int,
    vit         int,
    agi         int,
    mnd         int,
    appearance  jsonb       NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    UNIQUE (account_id, slot)
);
