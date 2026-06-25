"""
test_radius_server.py — Tests unitaires pour radius_server.py
Couverture : flux complet d'accès, accept/reject, intégration des modules, journalisation.
"""

import os
import tempfile

import pytest

from audit_logger import AuditLogger
from auth_backend import AuthBackend
from policy_engine import PolicyEngine
from radius_server import (
    RadiusServer,
    RADIUS_ACCESS_ACCEPT,
    RADIUS_ACCESS_REJECT,
)

SCHEMA_PATH = os.path.join(os.path.dirname(__file__), "..", "database", "schema.sql")


# ── Fixtures ─────────────────────────────────────────────────────────

@pytest.fixture
def server():
    """Crée un serveur RADIUS complet avec tous ses modules réels."""
    # Bases temporaires
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        auth_db = f.name
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        audit_db = f.name

    auth = AuthBackend(db_path=auth_db, schema_path=SCHEMA_PATH)
    policy = PolicyEngine()
    audit = AuditLogger(db_path=audit_db, hmac_key=os.urandom(32))

    # Création d'utilisateurs de test
    auth.create_user("eliel", "MotDePasse123!", "employe")
    auth.create_user("visiteur", "InvitePass!", "invite")
    auth.create_user("suspect", "SuspectPass!", "quarantaine")

    srv = RadiusServer(
        auth_backend=auth,
        policy_engine=policy,
        audit_logger=audit,
        shared_secret="secret-radius-test",
    )
    yield srv
    os.unlink(auth_db)
    os.unlink(audit_db)


# ── Tests d'accès accepté ─────────────────────────────────────────────

class TestAccessAccept:

    def test_employe_accepte_vlan10(self, server):
        """Un employé valide doit être accepté sur le VLAN 10."""
        resp = server.handle_access_request(
            session_id="s1", username="eliel", password="MotDePasse123!",
            mac_address="AA:BB:CC:DD:EE:FF", ip_nas="192.168.1.1"
        )
        assert resp["code"] == RADIUS_ACCESS_ACCEPT
        assert resp["vlan"] == "10"

    def test_invite_accepte_vlan20(self, server):
        """Un invité valide doit être accepté sur le VLAN 20."""
        resp = server.handle_access_request(
            session_id="s2", username="visiteur", password="InvitePass!",
            mac_address="AA:BB:CC:DD:EE:01", ip_nas="192.168.1.1"
        )
        assert resp["code"] == RADIUS_ACCESS_ACCEPT
        assert resp["vlan"] == "20"

    def test_attributs_radius_presents(self, server):
        """Une réponse acceptée doit contenir les attributs RADIUS de VLAN."""
        resp = server.handle_access_request(
            session_id="s3", username="eliel", password="MotDePasse123!",
            mac_address="AA:BB:CC:DD:EE:FF", ip_nas="192.168.1.1"
        )
        attrs = resp["attributes"]
        assert attrs["Tunnel-Private-Group-ID"] == "10"


# ── Tests d'accès rejeté ──────────────────────────────────────────────

class TestAccessReject:

    def test_mauvais_mot_de_passe(self, server):
        """Un mauvais mot de passe doit être rejeté."""
        resp = server.handle_access_request(
            session_id="s4", username="eliel", password="MAUVAIS",
            mac_address="AA:BB:CC:DD:EE:FF", ip_nas="192.168.1.1"
        )
        assert resp["code"] == RADIUS_ACCESS_REJECT
        assert resp["vlan"] is None

    def test_utilisateur_inconnu(self, server):
        """Un utilisateur inconnu doit être rejeté."""
        resp = server.handle_access_request(
            session_id="s5", username="pirate", password="hack",
            mac_address="FF:FF:FF:FF:FF:FF", ip_nas="192.168.1.1"
        )
        assert resp["code"] == RADIUS_ACCESS_REJECT


# ── Tests de quarantaine ──────────────────────────────────────────────

class TestQuarantaine:

    def test_role_quarantaine_vlan99(self, server):
        """Un compte en quarantaine doit aller sur le VLAN 99."""
        resp = server.handle_access_request(
            session_id="s6", username="suspect", password="SuspectPass!",
            mac_address="AA:BB:CC:DD:EE:02", ip_nas="192.168.1.1"
        )
        assert resp["code"] == RADIUS_ACCESS_ACCEPT
        assert resp["vlan"] == "99"

    def test_mac_bloquee_va_en_quarantaine(self, server):
        """Une MAC bloquée doit aller en quarantaine malgré un rôle valide."""
        server.policy_engine.block_mac("AA:BB:CC:DD:EE:FF")
        resp = server.handle_access_request(
            session_id="s7", username="eliel", password="MotDePasse123!",
            mac_address="AA:BB:CC:DD:EE:FF", ip_nas="192.168.1.1"
        )
        assert resp["vlan"] == "99"


# ── Tests de journalisation ───────────────────────────────────────────

class TestJournalisation:

    def test_acces_journalise(self, server):
        """Chaque accès doit être journalisé dans l'audit."""
        server.handle_access_request(
            session_id="s8", username="eliel", password="MotDePasse123!",
            mac_address="AA:BB:CC:DD:EE:FF", ip_nas="192.168.1.1"
        )
        stats = server.get_stats()
        assert stats["accepts"] == 1

    def test_rejet_journalise(self, server):
        """Un rejet doit aussi être journalisé."""
        server.handle_access_request(
            session_id="s9", username="eliel", password="MAUVAIS",
            mac_address="AA:BB:CC:DD:EE:FF", ip_nas="192.168.1.1"
        )
        stats = server.get_stats()
        assert stats["rejects"] == 1

    def test_integrite_journal_apres_acces(self, server):
        """Le journal doit rester intègre après plusieurs accès."""
        server.handle_access_request(
            session_id="s10", username="eliel", password="MotDePasse123!",
            mac_address="AA:BB:CC:DD:EE:FF", ip_nas="192.168.1.1"
        )
        server.handle_access_request(
            session_id="s11", username="pirate", password="hack",
            mac_address="FF:FF:FF:FF:FF:FF", ip_nas="192.168.1.1"
        )
        rapport = server.audit_logger.verify_integrity()
        assert rapport["valid"] is True
        assert rapport["total"] == 2


# ── Tests de gestion des sessions ─────────────────────────────────────

class TestSessions:

    def test_session_nettoyee_apres_acces(self, server):
        """La session doit être nettoyée après un accès complet."""
        server.handle_access_request(
            session_id="s12", username="eliel", password="MotDePasse123!",
            mac_address="AA:BB:CC:DD:EE:FF", ip_nas="192.168.1.1"
        )
        assert server.active_sessions_count() == 0

    def test_initialisation_serveur(self, server):
        """Le serveur doit être correctement initialisé."""
        assert server.port == 1812
        assert server.shared_secret == "secret-radius-test"
