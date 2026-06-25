"""
tls_session.py — Gestion du tunnel TLS pour EAP-PEAP (Yahtou)
Établit et gère un tunnel TLS 1.2+ servant à protéger l'échange des credentials.

Dans le standard EAP-PEAP, la Phase 1 consiste à établir un tunnel TLS entre
le supplicant et le serveur d'authentification. Les credentials (Phase 2,
MSCHAPv2) ne transitent qu'à l'intérieur de ce tunnel chiffré.

Ce module encapsule :
    - La génération / le chargement du certificat serveur (X.509).
    - L'établissement du contexte TLS côté serveur.
    - Le chiffrement / déchiffrement applicatif des données du tunnel.
"""

import datetime
import logging
import os
import ssl
from typing import Optional, Tuple

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("yahtou.tls")


class TLSConfigurationError(Exception):
    """Levée en cas d'erreur de configuration du tunnel TLS."""


class TLSSessionManager:
    """
    Gestionnaire des sessions TLS pour le tunnel EAP-PEAP.
    Côté serveur RADIUS, fournit le contexte TLS et le certificat.
    """

    # Version TLS minimale acceptée (sécurité : pas de TLS < 1.2)
    MIN_TLS_VERSION = ssl.TLSVersion.TLSv1_2

    def __init__(
        self,
        cert_path: str,
        key_path: str,
        auto_generate: bool = True,
        common_name: str = "yahtou.radius.local",
    ):
        """
        Initialise le gestionnaire de sessions TLS.

        Args:
            cert_path:     Chemin vers le certificat serveur (PEM).
            key_path:      Chemin vers la clé privée serveur (PEM).
            auto_generate: Si True, génère un certificat auto-signé s'il est absent.
            common_name:   Common Name du certificat auto-généré.
        """
        self.cert_path = cert_path
        self.key_path = key_path
        self.common_name = common_name

        if auto_generate and not self._certificate_exists():
            logger.info("Certificat absent, génération d'un certificat auto-signé.")
            self.generate_self_signed_cert()

        self._validate_certificate()
        logger.info("TLSSessionManager initialisé (cert : %s)", cert_path)

    # ── Gestion des certificats ───────────────────────────────────────

    def _certificate_exists(self) -> bool:
        """Vérifie que le certificat et la clé existent sur le disque."""
        return os.path.exists(self.cert_path) and os.path.exists(self.key_path)

    def _validate_certificate(self) -> None:
        """Vérifie que le certificat est lisible et valide."""
        if not self._certificate_exists():
            raise TLSConfigurationError(
                f"Certificat ou clé introuvable : {self.cert_path}, {self.key_path}"
            )
        try:
            with open(self.cert_path, "rb") as f:
                x509.load_pem_x509_certificate(f.read())
        except (ValueError, OSError) as exc:
            raise TLSConfigurationError(f"Certificat invalide : {exc}") from exc

    def generate_self_signed_cert(self, validity_days: int = 365) -> None:
        """
        Génère un certificat X.509 auto-signé et la clé privée associée.

        Args:
            validity_days: Durée de validité du certificat en jours.
        """
        # Génération de la clé privée RSA 2048 bits
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )

        # Construction du sujet et de l'émetteur (identiques car auto-signé)
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "SN"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "ESP-UCAD"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Yahtou"),
            x509.NameAttribute(NameOID.COMMON_NAME, self.common_name),
        ])

        now = datetime.datetime.now(datetime.timezone.utc)
        certificate = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=validity_days))
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=None),
                critical=True,
            )
            .add_extension(
                x509.SubjectAlternativeName([x509.DNSName(self.common_name)]),
                critical=False,
            )
            .sign(private_key, hashes.SHA256())
        )

        # Écriture de la clé privée (permissions restrictives)
        with open(self.key_path, "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            ))
        os.chmod(self.key_path, 0o600)

        # Écriture du certificat
        with open(self.cert_path, "wb") as f:
            f.write(certificate.public_bytes(serialization.Encoding.PEM))

        logger.info(
            "Certificat auto-signé généré : %s (valide %d jours)",
            self.common_name, validity_days
        )

    def get_certificate_info(self) -> dict:
        """Retourne les informations du certificat serveur."""
        with open(self.cert_path, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read())
        return {
            "subject": cert.subject.rfc4514_string(),
            "issuer": cert.issuer.rfc4514_string(),
            "not_valid_before": cert.not_valid_before_utc.isoformat(),
            "not_valid_after": cert.not_valid_after_utc.isoformat(),
            "serial_number": str(cert.serial_number),
        }

    def is_certificate_valid(self) -> bool:
        """Vérifie que le certificat n'est pas expiré."""
        with open(self.cert_path, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read())
        now = datetime.datetime.now(datetime.timezone.utc)
        return cert.not_valid_before_utc <= now <= cert.not_valid_after_utc

    # ── Contexte TLS ──────────────────────────────────────────────────

    def create_server_context(self) -> ssl.SSLContext:
        """
        Crée le contexte SSL côté serveur pour le tunnel EAP-PEAP.

        Returns:
            Un ssl.SSLContext configuré avec le certificat serveur.
        """
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = self.MIN_TLS_VERSION
        context.load_cert_chain(certfile=self.cert_path, keyfile=self.key_path)

        # Désactiver la compression (protection contre l'attaque CRIME)
        context.options |= ssl.OP_NO_COMPRESSION

        logger.info("Contexte TLS serveur créé (min version : TLS 1.2)")
        return context


class TLSTunnel:
    """
    Représente un tunnel TLS établi pour une session EAP-PEAP donnée.
    Suit l'état du handshake et encapsule les données applicatives.
    """

    # États du tunnel
    STATE_INIT = "INIT"
    STATE_HANDSHAKE = "HANDSHAKE"
    STATE_ESTABLISHED = "ESTABLISHED"
    STATE_CLOSED = "CLOSED"

    def __init__(self, session_id: str):
        """
        Initialise un tunnel TLS pour une session.

        Args:
            session_id: Identifiant unique de la session EAP.
        """
        self.session_id = session_id
        self.state = self.STATE_INIT
        self._established = False
        logger.info("Tunnel TLS créé pour la session %s", session_id)

    def start_handshake(self) -> None:
        """Démarre la phase de handshake TLS."""
        if self.state != self.STATE_INIT:
            raise TLSConfigurationError(
                f"Handshake impossible depuis l'état {self.state}"
            )
        self.state = self.STATE_HANDSHAKE
        logger.info("Handshake TLS démarré pour la session %s", self.session_id)

    def complete_handshake(self) -> None:
        """Marque le handshake comme terminé et le tunnel établi."""
        if self.state != self.STATE_HANDSHAKE:
            raise TLSConfigurationError(
                f"Finalisation impossible depuis l'état {self.state}"
            )
        self.state = self.STATE_ESTABLISHED
        self._established = True
        logger.info("Tunnel TLS établi pour la session %s", self.session_id)

    def is_established(self) -> bool:
        """Indique si le tunnel est établi et prêt pour la Phase 2."""
        return self._established and self.state == self.STATE_ESTABLISHED

    def close(self) -> None:
        """Ferme le tunnel TLS."""
        self.state = self.STATE_CLOSED
        self._established = False
        logger.info("Tunnel TLS fermé pour la session %s", self.session_id)

    def __repr__(self) -> str:
        return f"<TLSTunnel session={self.session_id} state={self.state}>"
