-- ============================================================
-- schema.sql — Schéma de la base de données Yahtou
-- Système d'authentification LAN basé sur IEEE 802.1X
-- ============================================================

-- Table des rôles
-- Chaque rôle est associé à un VLAN d'assignation.
CREATE TABLE IF NOT EXISTS roles (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT    NOT NULL UNIQUE,    -- 'employe', 'invite', 'quarantaine'
    vlan_id     TEXT    NOT NULL,            -- '10', '20', '99'
    description TEXT
);

-- Table des utilisateurs (machines / comptes)
-- Le mot de passe est stocké sous forme de hachage bcrypt.
CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT    NOT NULL UNIQUE,
    password_hash TEXT    NOT NULL,          -- hachage bcrypt
    role_id       INTEGER NOT NULL,
    active        INTEGER NOT NULL DEFAULT 1, -- 1 = actif, 0 = désactivé
    created_at    TEXT    NOT NULL,
    FOREIGN KEY (role_id) REFERENCES roles(id)
);

-- Table des administrateurs du portail
CREATE TABLE IF NOT EXISTS admins (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT    NOT NULL UNIQUE,
    password_hash TEXT    NOT NULL,          -- hachage bcrypt
    role          TEXT    NOT NULL DEFAULT 'admin', -- 'super-admin', 'auditeur'
    active        INTEGER NOT NULL DEFAULT 1,
    created_at    TEXT    NOT NULL
);

-- Index pour accélérer les recherches par nom d'utilisateur
CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
CREATE INDEX IF NOT EXISTS idx_admins_username ON admins(username);

-- ============================================================
-- Données initiales : les trois rôles standard de Yahtou
-- ============================================================
INSERT OR IGNORE INTO roles (name, vlan_id, description) VALUES
    ('employe',     '10', 'Acces complet au reseau de production'),
    ('invite',      '20', 'Acces Internet uniquement, reseau isole'),
    ('quarantaine', '99', 'Port bloque, machine suspecte ou non conforme');
