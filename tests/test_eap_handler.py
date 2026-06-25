"""
test_eap_handler.py — Tests unitaires pour eap_handler.py
Couverture : machine à états, flux complet EAP-PEAP, succès/échec, transitions.
"""

import pytest

from eap_handler import (
    EAPHandler,
    EAPError,
    EAP_SUCCESS,
    EAP_FAILURE,
)


# ── Callbacks simulés ────────────────────────────────────────────────

def callback_succes(username, password):
    """Simule une authentification réussie."""
    if username == "eliel" and password == "bonmotdepasse":
        return {"username": "eliel", "role": "employe", "vlan_id": "10"}
    return None


def callback_echec(username, password):
    """Simule une authentification toujours échouée."""
    return None


# ── Fixtures ─────────────────────────────────────────────────────────

@pytest.fixture
def handler():
    """Crée un EAPHandler avec callback de succès."""
    return EAPHandler(session_id="sess-test", auth_callback=callback_succes)


# ── Tests d'état initial ──────────────────────────────────────────────

class TestEtatInitial:

    def test_etat_initial_idle(self, handler):
        """Un nouveau handler doit être à l'état IDLE."""
        assert handler.state == EAPHandler.STATE_IDLE
        assert handler.is_complete() is False
        assert handler.is_successful() is False

    def test_tunnel_cree(self, handler):
        """Un tunnel TLS doit être créé à l'initialisation."""
        assert handler.tunnel is not None
        assert handler.tunnel.session_id == "sess-test"


# ── Tests du flux complet ─────────────────────────────────────────────

class TestFluxComplet:

    def test_flux_authentification_reussie(self, handler):
        """Le flux complet avec credentials valides doit réussir."""
        # Phase identité (enchaîne sur TLS-Start)
        resp = handler.handle_identity("eliel")
        assert resp["phase"] == "tls_start"

        # Phase handshake TLS
        resp = handler.handle_tls_handshake()
        assert resp["tunnel_ready"] is True

        # Phase MSCHAPv2 avec bons credentials
        resp = handler.handle_mschapv2("eliel", "bonmotdepasse")
        assert resp["code"] == EAP_SUCCESS
        assert handler.is_successful() is True
        assert resp["auth_result"]["vlan_id"] == "10"

    def test_flux_authentification_echouee(self, handler):
        """Le flux avec mauvais credentials doit échouer en MSCHAPv2."""
        handler.handle_identity("eliel")
        handler.handle_tls_handshake()
        resp = handler.handle_mschapv2("eliel", "mauvais_mdp")
        assert resp["code"] == EAP_FAILURE
        assert handler.state == EAPHandler.STATE_FAILURE
        assert handler.is_successful() is False

    def test_session_complete_apres_succes(self, handler):
        """Après un succès, la session doit être marquée complète."""
        handler.handle_identity("eliel")
        handler.handle_tls_handshake()
        handler.handle_mschapv2("eliel", "bonmotdepasse")
        assert handler.is_complete() is True


# ── Tests de la phase identité ────────────────────────────────────────

class TestPhaseIdentite:

    def test_identite_vide_echoue(self, handler):
        """Une identité vide doit provoquer une erreur EAP."""
        with pytest.raises(EAPError, match="Identité vide"):
            handler.handle_identity("")

    def test_identite_enregistree(self, handler):
        """L'identité doit être mémorisée après réception."""
        handler.handle_identity("eliel")
        assert handler.identity == "eliel"


# ── Tests des transitions ─────────────────────────────────────────────

class TestTransitions:

    def test_mschapv2_sans_tunnel_echoue(self, handler):
        """MSCHAPv2 avant l'établissement du tunnel doit échouer."""
        with pytest.raises(EAPError, match="tunnel TLS non établi"):
            handler.handle_mschapv2("eliel", "bonmotdepasse")

    def test_transition_interdite(self, handler):
        """Une transition non autorisée doit lever une erreur."""
        handler.handle_identity("eliel")
        handler.handle_tls_handshake()
        handler.handle_mschapv2("eliel", "bonmotdepasse")
        # La session est en SUCCESS, plus aucune transition possible
        with pytest.raises(EAPError, match="Transition interdite"):
            handler.start_tls()


# ── Tests du callback ─────────────────────────────────────────────────

class TestCallback:

    def test_sans_callback(self):
        """Un handler sans callback doit échouer en MSCHAPv2."""
        handler = EAPHandler(session_id="sess-no-cb", auth_callback=None)
        handler.handle_identity("eliel")
        handler.handle_tls_handshake()
        with pytest.raises(EAPError, match="Aucun callback"):
            handler.handle_mschapv2("eliel", "pass")

    def test_callback_leve_exception(self):
        """Si le callback lève une exception, l'auth doit échouer proprement."""
        def callback_exception(username, password):
            raise ValueError("Erreur interne")

        handler = EAPHandler(session_id="sess-exc", auth_callback=callback_exception)
        handler.handle_identity("eliel")
        handler.handle_tls_handshake()
        resp = handler.handle_mschapv2("eliel", "pass")
        assert resp["code"] == EAP_FAILURE


# ── Tests de réinitialisation ─────────────────────────────────────────

class TestReinitialisation:

    def test_reset(self, handler):
        """La réinitialisation doit remettre le handler à l'état IDLE."""
        handler.handle_identity("eliel")
        handler.reset()
        assert handler.state == EAPHandler.STATE_IDLE
        assert handler.identity is None
        assert handler.auth_result is None

    def test_reset_permet_nouvelle_tentative(self, handler):
        """Après reset, un nouveau flux complet doit être possible."""
        handler.handle_identity("eliel")
        handler.handle_tls_handshake()
        handler.handle_mschapv2("eliel", "mauvais_mdp")
        # Échec, on réinitialise et on réessaie
        handler.reset()
        handler.handle_identity("eliel")
        handler.handle_tls_handshake()
        resp = handler.handle_mschapv2("eliel", "bonmotdepasse")
        assert resp["code"] == EAP_SUCCESS

    def test_repr(self, handler):
        """La représentation du handler doit être lisible."""
        assert "sess-test" in repr(handler)
        assert "IDLE" in repr(handler)
