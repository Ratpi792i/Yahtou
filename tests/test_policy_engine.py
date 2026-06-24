"""
test_policy_engine.py — Tests unitaires pour policy_engine.py
Couverture : décisions d'accès, quarantaine, liste de blocage, attributs RADIUS.
"""

import pytest

from policy_engine import (
    PolicyEngine,
    PolicyDecision,
    TUNNEL_TYPE_VLAN,
    TUNNEL_MEDIUM_IEEE_802,
)


# ── Fixtures ─────────────────────────────────────────────────────────

@pytest.fixture
def engine():
    """Crée un PolicyEngine avec la configuration par défaut."""
    return PolicyEngine()


def employe_auth():
    """Résultat d'authentification d'un employé."""
    return {"username": "eliel", "role": "employe", "vlan_id": "10"}


def invite_auth():
    """Résultat d'authentification d'un invité."""
    return {"username": "visiteur", "role": "invite", "vlan_id": "20"}


def quarantaine_auth():
    """Résultat d'authentification d'un compte en quarantaine."""
    return {"username": "suspect", "role": "quarantaine", "vlan_id": "99"}


# ── Tests de décision nominale ────────────────────────────────────────

class TestDecisionNominale:

    def test_employe_accepte(self, engine):
        """Un employé doit être accepté sur le VLAN 10."""
        decision = engine.evaluate(employe_auth(), "AA:BB:CC:DD:EE:FF")
        assert decision.accept is True
        assert decision.vlan_id == "10"

    def test_invite_accepte(self, engine):
        """Un invité doit être accepté sur le VLAN 20."""
        decision = engine.evaluate(invite_auth(), "AA:BB:CC:DD:EE:01")
        assert decision.accept is True
        assert decision.vlan_id == "20"

    def test_echec_auth_rejete(self, engine):
        """Une authentification échouée (None) doit être rejetée."""
        decision = engine.evaluate(None, "AA:BB:CC:DD:EE:FF")
        assert decision.accept is False
        assert decision.vlan_id is None


# ── Tests de quarantaine ──────────────────────────────────────────────

class TestQuarantaine:

    def test_role_quarantaine(self, engine):
        """Un rôle quarantaine doit être placé sur le VLAN 99."""
        decision = engine.evaluate(quarantaine_auth(), "AA:BB:CC:DD:EE:FF")
        assert decision.accept is True
        assert decision.vlan_id == "99"

    def test_vlan_manquant_redirige_quarantaine(self, engine):
        """Un rôle sans VLAN doit être redirigé vers la quarantaine."""
        auth = {"username": "x", "role": "employe", "vlan_id": None}
        decision = engine.evaluate(auth, "AA:BB:CC:DD:EE:FF")
        assert decision.accept is True
        assert decision.vlan_id == "99"


# ── Tests de la liste de blocage ──────────────────────────────────────

class TestListeBlocage:

    def test_mac_bloquee_va_en_quarantaine(self, engine):
        """Une MAC bloquée doit aller en quarantaine même avec un rôle valide."""
        engine.block_mac("AA:BB:CC:DD:EE:FF")
        decision = engine.evaluate(employe_auth(), "AA:BB:CC:DD:EE:FF")
        assert decision.accept is True
        assert decision.vlan_id == "99"

    def test_mac_bloquee_insensible_casse(self, engine):
        """Le blocage de MAC doit être insensible à la casse."""
        engine.block_mac("aa:bb:cc:dd:ee:ff")
        assert engine.is_blocked("AA:BB:CC:DD:EE:FF") is True

    def test_deblocage_mac(self, engine):
        """Une MAC débloquée doit retrouver son VLAN normal."""
        engine.block_mac("AA:BB:CC:DD:EE:FF")
        engine.unblock_mac("AA:BB:CC:DD:EE:FF")
        decision = engine.evaluate(employe_auth(), "AA:BB:CC:DD:EE:FF")
        assert decision.vlan_id == "10"

    def test_is_blocked_faux_par_defaut(self, engine):
        """Une MAC inconnue ne doit pas être bloquée."""
        assert engine.is_blocked("11:22:33:44:55:66") is False


# ── Tests des attributs RADIUS ────────────────────────────────────────

class TestAttributsRadius:

    def test_attributs_accept(self, engine):
        """Une décision ACCEPT doit générer les 3 attributs RADIUS de VLAN."""
        decision = engine.evaluate(employe_auth(), "AA:BB:CC:DD:EE:FF")
        attrs = decision.to_radius_attributes()
        assert attrs["Tunnel-Type"] == TUNNEL_TYPE_VLAN
        assert attrs["Tunnel-Medium-Type"] == TUNNEL_MEDIUM_IEEE_802
        assert attrs["Tunnel-Private-Group-ID"] == "10"

    def test_attributs_reject_vides(self, engine):
        """Une décision REJECT ne doit générer aucun attribut."""
        decision = engine.evaluate(None, "AA:BB:CC:DD:EE:FF")
        attrs = decision.to_radius_attributes()
        assert attrs == {}

    def test_repr_decision(self, engine):
        """La représentation textuelle d'une décision doit être lisible."""
        decision = engine.evaluate(employe_auth(), "AA:BB:CC:DD:EE:FF")
        texte = repr(decision)
        assert "ACCEPT" in texte
        assert "10" in texte


# ── Tests de configuration ────────────────────────────────────────────

class TestConfiguration:

    def test_vlan_quarantaine_personnalise(self):
        """Le VLAN de quarantaine doit être configurable."""
        engine = PolicyEngine(quarantine_vlan="999")
        engine.block_mac("AA:BB:CC:DD:EE:FF")
        decision = engine.evaluate(employe_auth(), "AA:BB:CC:DD:EE:FF")
        assert decision.vlan_id == "999"


def employe_auth():
    """Résultat d'authentification d'un employé (réutilisé dans les classes)."""
    return {"username": "eliel", "role": "employe", "vlan_id": "10"}
