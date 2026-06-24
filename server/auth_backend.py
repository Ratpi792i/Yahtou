"""
auth_backend.py — Module de vérification des credentials pour Yahtou
Gère l'authentification des utilisateurs contre la base SQLite avec bcrypt.

Responsabilités :
    - Création et gestion des comptes utilisateurs (machines).
    - Vérification des credentials (bcrypt).
    - Gestion des rôles et de leur VLAN associé.
    - Activation / désactivation des comptes.
"""

import logging
import os
import sqlite3
from datetime import datetime, timezone
from typing import Optional

import bcrypt

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("yahtou.auth")


class AuthenticationError(Exception):
    """Levée lorsqu'une authentification échoue pour une raison non technique."""


class AuthBackend:
    """
    Backend d'authentification de Yahtou.
    Vérifie les credentials des utilisateurs contre la base SQLite.
    """

    BCRYPT_ROUNDS = 12  # Coût bcrypt (résistance au bruteforce)

    def __init__(self, db_path: str, schema_path: Optional[str] = None):
        """
        Initialise le backend d'authentification.

        Args:
            db_path:     Chemin vers la base SQLite.
            schema_path: Chemin optionnel vers schema.sql pour initialiser la base.
        """
        self.db_path = db_path
        if schema_path:
            self._init_schema(schema_path)
        logger.info("AuthBackend initialisé — base : %s", db_path)

    # ── Initialisation ────────────────────────────────────────────────

    def _connect(self) -> sqlite3.Connection:
        """Retourne une connexion SQLite avec les clés étrangères activées."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        return conn

    def _init_schema(self, schema_path: str) -> None:
        """Exécute le script SQL de création du schéma."""
        if not os.path.exists(schema_path):
            raise FileNotFoundError(f"Schéma introuvable : {schema_path}")
        with open(schema_path, encoding="utf-8") as f:
            schema_sql = f.read()
        with self._connect() as conn:
            conn.executescript(schema_sql)
        logger.info("Schéma initialisé depuis %s", schema_path)

    # ── Hachage ───────────────────────────────────────────────────────

    def _hash_password(self, password: str) -> str:
        """Hache un mot de passe avec bcrypt."""
        salt = bcrypt.gensalt(rounds=self.BCRYPT_ROUNDS)
        hashed = bcrypt.hashpw(password.encode("utf-8"), salt)
        return hashed.decode("utf-8")

    def _verify_password(self, password: str, password_hash: str) -> bool:
        """Vérifie un mot de passe contre son hachage bcrypt."""
        try:
            return bcrypt.checkpw(
                password.encode("utf-8"),
                password_hash.encode("utf-8")
            )
        except (ValueError, TypeError):
            logger.warning("Hachage invalide rencontré lors de la vérification.")
            return False

    # ── Gestion des utilisateurs ──────────────────────────────────────

    def create_user(self, username: str, password: str, role_name: str) -> int:
        """
        Crée un nouvel utilisateur (machine) avec un rôle donné.

        Args:
            username:  Identifiant unique de l'utilisateur.
            password:  Mot de passe en clair (sera haché).
            role_name: Nom du rôle ('employe', 'invite', 'quarantaine').

        Returns:
            L'identifiant du nouvel utilisateur.

        Raises:
            ValueError: Si le rôle n'existe pas ou si l'utilisateur existe déjà.
        """
        if not username or not password:
            raise ValueError("Le nom d'utilisateur et le mot de passe sont obligatoires.")

        with self._connect() as conn:
            role = conn.execute(
                "SELECT id FROM roles WHERE name = ?", (role_name,)
            ).fetchone()
            if not role:
                raise ValueError(f"Rôle inexistant : '{role_name}'")

            existing = conn.execute(
                "SELECT id FROM users WHERE username = ?", (username,)
            ).fetchone()
            if existing:
                raise ValueError(f"L'utilisateur '{username}' existe déjà.")

            password_hash = self._hash_password(password)
            timestamp = datetime.now(timezone.utc).isoformat()

            cursor = conn.execute(
                """
                INSERT INTO users (username, password_hash, role_id, active, created_at)
                VALUES (?, ?, ?, 1, ?)
                """,
                (username, password_hash, role["id"], timestamp)
            )
            user_id = cursor.lastrowid

        logger.info("Utilisateur créé : %s (rôle=%s)", username, role_name)
        return user_id

    def authenticate(self, username: str, password: str) -> dict:
        """
        Authentifie un utilisateur et retourne ses informations si valide.

        Args:
            username: Identifiant de l'utilisateur.
            password: Mot de passe en clair.

        Returns:
            dict avec les clés : username, role, vlan_id.

        Raises:
            AuthenticationError: Si l'authentification échoue.
        """
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT u.username, u.password_hash, u.active, r.name AS role, r.vlan_id
                FROM users u
                JOIN roles r ON u.role_id = r.id
                WHERE u.username = ?
                """,
                (username,)
            ).fetchone()

        if not row:
            logger.info("Authentification échouée : utilisateur '%s' inconnu.", username)
            raise AuthenticationError("Identifiants invalides.")

        if not row["active"]:
            logger.info("Authentification refusée : compte '%s' désactivé.", username)
            raise AuthenticationError("Compte désactivé.")

        if not self._verify_password(password, row["password_hash"]):
            logger.info("Authentification échouée : mot de passe incorrect pour '%s'.", username)
            raise AuthenticationError("Identifiants invalides.")

        logger.info("Authentification réussie : %s (rôle=%s)", username, row["role"])
        return {
            "username": row["username"],
            "role": row["role"],
            "vlan_id": row["vlan_id"],
        }

    def deactivate_user(self, username: str) -> bool:
        """Désactive un compte utilisateur. Retourne True si modifié."""
        with self._connect() as conn:
            cursor = conn.execute(
                "UPDATE users SET active = 0 WHERE username = ?", (username,)
            )
            modified = cursor.rowcount > 0
        if modified:
            logger.info("Compte désactivé : %s", username)
        return modified

    def activate_user(self, username: str) -> bool:
        """Réactive un compte utilisateur. Retourne True si modifié."""
        with self._connect() as conn:
            cursor = conn.execute(
                "UPDATE users SET active = 1 WHERE username = ?", (username,)
            )
            modified = cursor.rowcount > 0
        if modified:
            logger.info("Compte réactivé : %s", username)
        return modified

    def change_role(self, username: str, new_role_name: str) -> bool:
        """
        Change le rôle d'un utilisateur (et donc son VLAN).

        Returns:
            True si le rôle a été modifié.

        Raises:
            ValueError: Si le rôle ou l'utilisateur n'existe pas.
        """
        with self._connect() as conn:
            role = conn.execute(
                "SELECT id FROM roles WHERE name = ?", (new_role_name,)
            ).fetchone()
            if not role:
                raise ValueError(f"Rôle inexistant : '{new_role_name}'")

            cursor = conn.execute(
                "UPDATE users SET role_id = ? WHERE username = ?",
                (role["id"], username)
            )
            modified = cursor.rowcount > 0

        if modified:
            logger.info("Rôle modifié : %s -> %s", username, new_role_name)
        return modified

    def delete_user(self, username: str) -> bool:
        """Supprime définitivement un compte utilisateur."""
        with self._connect() as conn:
            cursor = conn.execute(
                "DELETE FROM users WHERE username = ?", (username,)
            )
            deleted = cursor.rowcount > 0
        if deleted:
            logger.info("Compte supprimé : %s", username)
        return deleted

    # ── Consultation ──────────────────────────────────────────────────

    def get_user(self, username: str) -> Optional[dict]:
        """Retourne les informations d'un utilisateur (sans le hachage)."""
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT u.username, u.active, u.created_at, r.name AS role, r.vlan_id
                FROM users u
                JOIN roles r ON u.role_id = r.id
                WHERE u.username = ?
                """,
                (username,)
            ).fetchone()
        return dict(row) if row else None

    def list_users(self) -> list:
        """Retourne la liste de tous les utilisateurs (sans les hachages)."""
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT u.username, u.active, u.created_at, r.name AS role, r.vlan_id
                FROM users u
                JOIN roles r ON u.role_id = r.id
                ORDER BY u.username
                """
            ).fetchall()
        return [dict(row) for row in rows]

    def list_roles(self) -> list:
        """Retourne la liste des rôles disponibles."""
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT name, vlan_id, description FROM roles ORDER BY name"
            ).fetchall()
        return [dict(row) for row in rows]
