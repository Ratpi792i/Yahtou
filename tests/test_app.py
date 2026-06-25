"""
test_app.py — Tests unitaires pour le portail Flask (app.py)
Couverture : authentification, contrôle d'accès, gestion utilisateurs, RBAC, sécurité.
"""

import os
import tempfile

import pytest

from app import create_app, _ensure_admin_table


SCHEMA_PATH = os.path.join(os.path.dirname(__file__), "..", "database", "schema.sql")


# ── Fixtures ─────────────────────────────────────────────────────────

@pytest.fixture
def client():
    """Crée un client de test Flask avec bases temporaires."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        audit_db = f.name

    config = {
        "TESTING": True,
        "WTF_CSRF_ENABLED": False,  # Désactive CSRF pour les tests
        "DB_PATH": db_path,
        "AUDIT_DB_PATH": audit_db,
        "SCHEMA_PATH": SCHEMA_PATH,
        "SECRET_KEY": "test-secret-key",
    }
    app = create_app(config)
    with app.test_client() as test_client:
        yield test_client

    os.unlink(db_path)
    os.unlink(audit_db)


def login(client, username="admin", password="admin123"):
    """Helper pour se connecter."""
    return client.post("/login", data={
        "username": username, "password": password
    }, follow_redirects=True)


# ── Tests d'authentification ──────────────────────────────────────────

class TestAuthentification:

    def test_page_login_accessible(self, client):
        """La page de connexion doit être accessible."""
        resp = client.get("/login")
        assert resp.status_code == 200
        assert b"Connexion administrateur" in resp.data

    def test_login_succes(self, client):
        """La connexion avec les bons credentials doit réussir."""
        resp = login(client)
        assert resp.status_code == 200
        assert "Tableau de bord".encode() in resp.data

    def test_login_echec(self, client):
        """La connexion avec de mauvais credentials doit échouer."""
        resp = login(client, password="mauvais")
        assert "Identifiants invalides".encode() in resp.data

    def test_logout(self, client):
        """La déconnexion doit fonctionner."""
        login(client)
        resp = client.get("/logout", follow_redirects=True)
        assert b"connect" in resp.data.lower()


# ── Tests de contrôle d'accès ─────────────────────────────────────────

class TestControleAcces:

    def test_dashboard_protege(self, client):
        """Le tableau de bord doit rediriger vers login sans session."""
        resp = client.get("/dashboard", follow_redirects=True)
        assert b"Connexion administrateur" in resp.data

    def test_users_protege(self, client):
        """La page utilisateurs doit être protégée."""
        resp = client.get("/users", follow_redirects=True)
        assert b"Connexion administrateur" in resp.data

    def test_logs_protege(self, client):
        """La page journaux doit être protégée."""
        resp = client.get("/logs", follow_redirects=True)
        assert b"Connexion administrateur" in resp.data

    def test_acces_apres_login(self, client):
        """Après connexion, les pages doivent être accessibles."""
        login(client)
        assert client.get("/dashboard").status_code == 200
        assert client.get("/users").status_code == 200
        assert client.get("/logs").status_code == 200


# ── Tests de gestion des utilisateurs ─────────────────────────────────

class TestGestionUtilisateurs:

    def test_creer_utilisateur(self, client):
        """La création d'un utilisateur doit fonctionner."""
        login(client)
        resp = client.post("/users/create", data={
            "username": "testuser", "password": "pass123", "role": "employe"
        }, follow_redirects=True)
        assert "testuser".encode() in resp.data

    def test_creer_utilisateur_role_invalide(self, client):
        """Créer un utilisateur avec un rôle invalide doit afficher une erreur."""
        login(client)
        resp = client.post("/users/create", data={
            "username": "testuser", "password": "pass123", "role": "inexistant"
        }, follow_redirects=True)
        assert "inexistant".encode() in resp.data.lower() or b"error" in resp.data.lower()

    def test_changer_role(self, client):
        """Le changement de rôle doit fonctionner."""
        login(client)
        client.post("/users/create", data={
            "username": "testuser", "password": "pass123", "role": "employe"
        })
        resp = client.post("/users/testuser/role", data={
            "role": "invite"
        }, follow_redirects=True)
        assert resp.status_code == 200

    def test_toggle_utilisateur(self, client):
        """L'activation/désactivation doit fonctionner."""
        login(client)
        client.post("/users/create", data={
            "username": "testuser", "password": "pass123", "role": "employe"
        })
        resp = client.post("/users/testuser/toggle", follow_redirects=True)
        assert resp.status_code == 200

    def test_supprimer_utilisateur(self, client):
        """La suppression d'un utilisateur doit fonctionner."""
        login(client)
        client.post("/users/create", data={
            "username": "testuser", "password": "pass123", "role": "employe"
        })
        resp = client.post("/users/testuser/delete", follow_redirects=True)
        assert resp.status_code == 200


# ── Tests des journaux ────────────────────────────────────────────────

class TestJournaux:

    def test_page_logs(self, client):
        """La page des journaux doit s'afficher."""
        login(client)
        resp = client.get("/logs")
        assert resp.status_code == 200
        assert "Journaux d'audit".encode() in resp.data

    def test_integrite_affichee(self, client):
        """Le bandeau d'intégrité doit être affiché."""
        login(client)
        resp = client.get("/logs")
        assert "Intégrité".encode() in resp.data


# ── Tests de sécurité ─────────────────────────────────────────────────

class TestSecurite:

    def test_index_redirige(self, client):
        """La racine doit rediriger vers login si non connecté."""
        resp = client.get("/", follow_redirects=True)
        assert b"Connexion administrateur" in resp.data

    def test_page_404(self, client):
        """Une page inexistante doit retourner 404."""
        login(client)
        resp = client.get("/page-inexistante")
        assert resp.status_code == 404
