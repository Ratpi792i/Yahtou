"""
test_tls_session.py — Tests unitaires pour tls_session.py
Couverture : génération de certificat, contexte TLS, machine à états du tunnel.
"""

import os
import ssl
import tempfile

import pytest

from tls_session import (
    TLSSessionManager,
    TLSTunnel,
    TLSConfigurationError,
)


# ── Fixtures ─────────────────────────────────────────────────────────

@pytest.fixture
def temp_paths():
    """Fournit des chemins temporaires pour le certificat et la clé."""
    tmpdir = tempfile.mkdtemp()
    cert_path = os.path.join(tmpdir, "server.crt")
    key_path = os.path.join(tmpdir, "server.key")
    yield cert_path, key_path
    for path in (cert_path, key_path):
        if os.path.exists(path):
            os.unlink(path)
    os.rmdir(tmpdir)


@pytest.fixture
def tls_manager(temp_paths):
    """Crée un TLSSessionManager avec certificat auto-généré."""
    cert_path, key_path = temp_paths
    return TLSSessionManager(cert_path=cert_path, key_path=key_path)


# ── Tests de génération de certificat ─────────────────────────────────

class TestGenerationCertificat:

    def test_certificat_genere(self, tls_manager):
        """Le certificat et la clé doivent être créés automatiquement."""
        assert os.path.exists(tls_manager.cert_path)
        assert os.path.exists(tls_manager.key_path)

    def test_certificat_valide(self, tls_manager):
        """Le certificat généré ne doit pas être expiré."""
        assert tls_manager.is_certificate_valid() is True

    def test_cle_permissions_restrictives(self, tls_manager):
        """La clé privée doit avoir des permissions restrictives (600)."""
        mode = oct(os.stat(tls_manager.key_path).st_mode)[-3:]
        assert mode == "600"

    def test_info_certificat(self, tls_manager):
        """Les informations du certificat doivent être lisibles."""
        info = tls_manager.get_certificate_info()
        assert "yahtou.radius.local" in info["subject"]
        assert "ESP-UCAD" in info["issuer"]
        assert "serial_number" in info

    def test_common_name_personnalise(self, temp_paths):
        """Le Common Name du certificat doit être configurable."""
        cert_path, key_path = temp_paths
        manager = TLSSessionManager(
            cert_path=cert_path, key_path=key_path,
            common_name="custom.yahtou.local"
        )
        info = manager.get_certificate_info()
        assert "custom.yahtou.local" in info["subject"]


# ── Tests du contexte TLS ─────────────────────────────────────────────

class TestContexteTLS:

    def test_creation_contexte_serveur(self, tls_manager):
        """Le contexte TLS serveur doit être créé sans erreur."""
        context = tls_manager.create_server_context()
        assert isinstance(context, ssl.SSLContext)

    def test_version_tls_minimale(self, tls_manager):
        """Le contexte doit refuser les versions TLS < 1.2."""
        context = tls_manager.create_server_context()
        assert context.minimum_version == ssl.TLSVersion.TLSv1_2

    def test_compression_desactivee(self, tls_manager):
        """La compression TLS doit être désactivée (protection CRIME)."""
        context = tls_manager.create_server_context()
        assert context.options & ssl.OP_NO_COMPRESSION


# ── Tests de validation ───────────────────────────────────────────────

class TestValidation:

    def test_certificat_manquant_sans_autogen(self, temp_paths):
        """Sans auto-génération et sans certificat, une erreur doit être levée."""
        cert_path, key_path = temp_paths
        with pytest.raises(TLSConfigurationError):
            TLSSessionManager(
                cert_path=cert_path, key_path=key_path,
                auto_generate=False
            )


# ── Tests de la machine à états du tunnel ─────────────────────────────

class TestTunnelEtats:

    def test_etat_initial(self):
        """Un nouveau tunnel doit être à l'état INIT."""
        tunnel = TLSTunnel(session_id="sess-001")
        assert tunnel.state == TLSTunnel.STATE_INIT
        assert tunnel.is_established() is False

    def test_cycle_complet(self):
        """Le cycle INIT -> HANDSHAKE -> ESTABLISHED doit fonctionner."""
        tunnel = TLSTunnel(session_id="sess-002")
        tunnel.start_handshake()
        assert tunnel.state == TLSTunnel.STATE_HANDSHAKE
        tunnel.complete_handshake()
        assert tunnel.state == TLSTunnel.STATE_ESTABLISHED
        assert tunnel.is_established() is True

    def test_fermeture_tunnel(self):
        """La fermeture d'un tunnel doit le passer à l'état CLOSED."""
        tunnel = TLSTunnel(session_id="sess-003")
        tunnel.start_handshake()
        tunnel.complete_handshake()
        tunnel.close()
        assert tunnel.state == TLSTunnel.STATE_CLOSED
        assert tunnel.is_established() is False

    def test_handshake_depuis_mauvais_etat(self):
        """Démarrer un handshake deux fois doit lever une erreur."""
        tunnel = TLSTunnel(session_id="sess-004")
        tunnel.start_handshake()
        with pytest.raises(TLSConfigurationError):
            tunnel.start_handshake()

    def test_completion_sans_handshake(self):
        """Compléter un handshake non démarré doit lever une erreur."""
        tunnel = TLSTunnel(session_id="sess-005")
        with pytest.raises(TLSConfigurationError):
            tunnel.complete_handshake()

    def test_repr_tunnel(self):
        """La représentation du tunnel doit être lisible."""
        tunnel = TLSTunnel(session_id="sess-006")
        assert "sess-006" in repr(tunnel)
        assert "INIT" in repr(tunnel)
