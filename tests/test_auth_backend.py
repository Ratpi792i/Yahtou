"""
test_auth_backend.py — Tests unitaires pour auth_backend.py
Couverture : création, authentification, gestion des rôles, activation, consultation.
"""

import os
import tempfile

import pytest

from auth_backend import AuthBackend, AuthenticationError

# Chemin vers le schéma SQL (dans le même dossier que les modules)
SCHEMA_PATH = os.path.join(os.path.dirname(__file__), "..", "database", "schema.sql")


# ── Fixtures ─────────────────────────────────────────────────────────

@pytest.fixture
def auth():
    """Crée un AuthBackend temporaire avec le schéma initialisé."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name
    backend = AuthBackend(db_path=db_path, schema_path=SCHEMA_PATH)
    yield backend
    os.unlink(db_path)


# ── Tests de création ─────────────────────────────────────────────────

class TestCreationUtilisateur:

    def test_create_user(self, auth):
        """La création d'un utilisateur doit retourner un ID."""
        user_id = auth.create_user("eliel", "MotDePasse123!", "employe")
        assert user_id == 1

    def test_create_user_role_inexistant(self, auth):
        """Créer un utilisateur avec un rôle inexistant doit lever ValueError."""
        with pytest.raises(ValueError, match="Rôle inexistant"):
            auth.create_user("eliel", "pass123", "role_bidon")

    def test_create_user_doublon(self, auth):
        """Créer deux fois le même utilisateur doit lever ValueError."""
        auth.create_user("eliel", "pass123", "employe")
        with pytest.raises(ValueError, match="existe déjà"):
            auth.create_user("eliel", "autre_pass", "invite")

    def test_create_user_champs_vides(self, auth):
        """Créer un utilisateur sans nom ou mot de passe doit lever ValueError."""
        with pytest.raises(ValueError):
            auth.create_user("", "pass123", "employe")
        with pytest.raises(ValueError):
            auth.create_user("user", "", "employe")


# ── Tests d'authentification ──────────────────────────────────────────

class TestAuthentification:

    def test_authenticate_succes(self, auth):
        """Une authentification valide doit retourner les infos utilisateur."""
        auth.create_user("eliel", "MotDePasse123!", "employe")
        result = auth.authenticate("eliel", "MotDePasse123!")
        assert result["username"] == "eliel"
        assert result["role"] == "employe"
        assert result["vlan_id"] == "10"

    def test_authenticate_mauvais_mdp(self, auth):
        """Un mauvais mot de passe doit lever AuthenticationError."""
        auth.create_user("eliel", "MotDePasse123!", "employe")
        with pytest.raises(AuthenticationError, match="Identifiants invalides"):
            auth.authenticate("eliel", "mauvais_mdp")

    def test_authenticate_utilisateur_inconnu(self, auth):
        """Un utilisateur inconnu doit lever AuthenticationError."""
        with pytest.raises(AuthenticationError, match="Identifiants invalides"):
            auth.authenticate("inconnu", "pass123")

    def test_authenticate_compte_desactive(self, auth):
        """Un compte désactivé ne doit pas pouvoir s'authentifier."""
        auth.create_user("eliel", "MotDePasse123!", "employe")
        auth.deactivate_user("eliel")
        with pytest.raises(AuthenticationError, match="désactivé"):
            auth.authenticate("eliel", "MotDePasse123!")

    def test_mot_de_passe_non_stocke_en_clair(self, auth):
        """Le mot de passe ne doit jamais être stocké en clair."""
        import sqlite3
        auth.create_user("eliel", "MotDePasse123!", "employe")
        conn = sqlite3.connect(auth.db_path)
        row = conn.execute("SELECT password_hash FROM users WHERE username='eliel'").fetchone()
        conn.close()
        assert "MotDePasse123!" not in row[0]
        assert row[0].startswith("$2b$")  # préfixe bcrypt


# ── Tests de gestion des rôles ────────────────────────────────────────

class TestGestionRoles:

    def test_change_role(self, auth):
        """Le changement de rôle doit modifier le VLAN associé."""
        auth.create_user("eliel", "pass123", "employe")
        assert auth.change_role("eliel", "invite") is True
        result = auth.authenticate("eliel", "pass123")
        assert result["role"] == "invite"
        assert result["vlan_id"] == "20"

    def test_change_role_inexistant(self, auth):
        """Changer vers un rôle inexistant doit lever ValueError."""
        auth.create_user("eliel", "pass123", "employe")
        with pytest.raises(ValueError, match="Rôle inexistant"):
            auth.change_role("eliel", "role_bidon")

    def test_list_roles(self, auth):
        """Les trois rôles standard doivent être présents."""
        roles = auth.list_roles()
        noms = [r["name"] for r in roles]
        assert "employe" in noms
        assert "invite" in noms
        assert "quarantaine" in noms


# ── Tests d'activation ────────────────────────────────────────────────

class TestActivation:

    def test_deactivate_reactivate(self, auth):
        """Un compte désactivé puis réactivé doit pouvoir s'authentifier."""
        auth.create_user("eliel", "pass123", "employe")
        auth.deactivate_user("eliel")
        auth.activate_user("eliel")
        result = auth.authenticate("eliel", "pass123")
        assert result["username"] == "eliel"

    def test_deactivate_inexistant(self, auth):
        """Désactiver un compte inexistant doit retourner False."""
        assert auth.deactivate_user("inconnu") is False

    def test_delete_user(self, auth):
        """La suppression d'un compte doit fonctionner."""
        auth.create_user("eliel", "pass123", "employe")
        assert auth.delete_user("eliel") is True
        assert auth.get_user("eliel") is None


# ── Tests de consultation ─────────────────────────────────────────────

class TestConsultation:

    def test_get_user(self, auth):
        """get_user doit retourner les infos sans le hachage."""
        auth.create_user("eliel", "pass123", "employe")
        user = auth.get_user("eliel")
        assert user["username"] == "eliel"
        assert user["role"] == "employe"
        assert "password_hash" not in user

    def test_get_user_inexistant(self, auth):
        """get_user sur un utilisateur inexistant doit retourner None."""
        assert auth.get_user("inconnu") is None

    def test_list_users(self, auth):
        """list_users doit retourner tous les utilisateurs."""
        auth.create_user("eliel", "pass123", "employe")
        auth.create_user("amadou", "pass456", "invite")
        users = auth.list_users()
        assert len(users) == 2
        assert all("password_hash" not in u for u in users)
