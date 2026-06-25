"""
radius_server.py — Serveur RADIUS de Yahtou
Point d'entrée du système d'authentification : assemble tous les modules.

Le serveur écoute les requêtes RADIUS (UDP:1812) émises par le commutateur
(NAS / Authenticator) et orchestre le flux complet :

    1. Réception d'une demande d'accès (Access-Request).
    2. Déroulement du flux EAP-PEAP (eap_handler + tls_session).
    3. Validation des credentials (auth_backend).
    4. Décision d'attribution de VLAN (policy_engine).
    5. Journalisation de l'événement (audit_logger).
    6. Réponse : Access-Accept (+ attributs VLAN) ou Access-Reject.

Note : ce module implémente la logique d'assemblage et de traitement des
requêtes. La couche réseau UDP brute est volontairement abstraite pour
permettre les tests unitaires sans socket réel.
"""

import logging
from typing import Optional

from audit_logger import AuditLogger
from auth_backend import AuthBackend, AuthenticationError
from eap_handler import EAPHandler
from policy_engine import PolicyEngine

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("yahtou.radius")


# Codes RADIUS (RFC 2865)
RADIUS_ACCESS_REQUEST = 1
RADIUS_ACCESS_ACCEPT = 2
RADIUS_ACCESS_REJECT = 3
RADIUS_ACCESS_CHALLENGE = 11

DEFAULT_RADIUS_PORT = 1812


class RadiusServer:
    """
    Serveur RADIUS de Yahtou.
    Orchestre l'authentification, l'autorisation et la journalisation.
    """

    def __init__(
        self,
        auth_backend: AuthBackend,
        policy_engine: PolicyEngine,
        audit_logger: AuditLogger,
        shared_secret: str,
        port: int = DEFAULT_RADIUS_PORT,
    ):
        """
        Initialise le serveur RADIUS avec ses dépendances.

        Args:
            auth_backend:  Backend de vérification des credentials.
            policy_engine: Moteur de décision d'attribution de VLAN.
            audit_logger:  Journal d'audit infalsifiable.
            shared_secret: Secret partagé avec le commutateur (NAS).
            port:          Port UDP d'écoute (1812 par défaut).
        """
        self.auth_backend = auth_backend
        self.policy_engine = policy_engine
        self.audit_logger = audit_logger
        self.shared_secret = shared_secret
        self.port = port
        self._sessions = {}
        logger.info("RadiusServer initialisé (port UDP:%d)", port)

    # ── Gestion des sessions EAP ──────────────────────────────────────

    def _get_or_create_session(self, session_id: str) -> EAPHandler:
        """Récupère ou crée le gestionnaire EAP pour une session."""
        if session_id not in self._sessions:
            self._sessions[session_id] = EAPHandler(
                session_id=session_id,
                auth_callback=self._authenticate_callback,
            )
        return self._sessions[session_id]

    def _authenticate_callback(self, username: str, password: str) -> Optional[dict]:
        """
        Callback d'authentification appelé par eap_handler lors du MSCHAPv2.

        Returns:
            Le dict d'authentification si valide, None sinon.
        """
        try:
            return self.auth_backend.authenticate(username, password)
        except AuthenticationError:
            return None

    def _cleanup_session(self, session_id: str) -> None:
        """Supprime une session terminée."""
        self._sessions.pop(session_id, None)

    # ── Traitement d'une requête d'accès complète ─────────────────────

    def handle_access_request(
        self,
        session_id: str,
        username: str,
        password: str,
        mac_address: str,
        ip_nas: str,
    ) -> dict:
        """
        Traite une demande d'accès RADIUS complète, du début à la fin.

        Cette méthode déroule l'intégralité du flux : EAP-PEAP, validation,
        décision de VLAN et journalisation.

        Args:
            session_id:  Identifiant unique de la session.
            username:    Identité du supplicant.
            password:    Mot de passe du supplicant.
            mac_address: Adresse MAC de la machine cliente.
            ip_nas:      Adresse IP du commutateur.

        Returns:
            Un dict décrivant la réponse RADIUS :
                - code : RADIUS_ACCESS_ACCEPT ou RADIUS_ACCESS_REJECT
                - vlan : VLAN assigné (si accepté)
                - attributes : attributs RADIUS (si accepté)
        """
        handler = self._get_or_create_session(session_id)

        # 1. Déroulement du flux EAP-PEAP
        try:
            handler.handle_identity(username)
            handler.handle_tls_handshake()
            eap_result = handler.handle_mschapv2(username, password)
        except Exception as exc:  # pylint: disable=broad-except
            logger.warning("Erreur EAP pour la session %s : %s", session_id, exc)
            return self._reject(session_id, username, mac_address, ip_nas,
                                 reason="Erreur protocole EAP")

        # 2. Vérification du résultat EAP
        auth_result = eap_result.get("auth_result")

        # 3. Décision de politique (VLAN)
        decision = self.policy_engine.evaluate(auth_result, mac_address)

        # 4. Construction de la réponse selon la décision
        if decision.accept:
            return self._accept(session_id, username, mac_address, ip_nas, decision)
        return self._reject(session_id, username, mac_address, ip_nas,
                            reason=decision.reason)

    # ── Construction des réponses ─────────────────────────────────────

    def _accept(self, session_id, username, mac_address, ip_nas, decision) -> dict:
        """Construit une réponse Access-Accept et journalise."""
        self.audit_logger.log(
            identity=username,
            mac_address=mac_address,
            ip_nas=ip_nas,
            result="ACCEPT",
            vlan=decision.vlan_id,
        )
        self._cleanup_session(session_id)
        logger.info("Access-Accept : %s -> VLAN %s", username, decision.vlan_id)
        return {
            "code": RADIUS_ACCESS_ACCEPT,
            "vlan": decision.vlan_id,
            "attributes": decision.to_radius_attributes(),
            "username": username,
        }

    def _reject(self, session_id, username, mac_address, ip_nas, reason) -> dict:
        """Construit une réponse Access-Reject et journalise."""
        self.audit_logger.log(
            identity=username,
            mac_address=mac_address,
            ip_nas=ip_nas,
            result="REJECT",
            vlan=None,
        )
        self._cleanup_session(session_id)
        logger.info("Access-Reject : %s (%s)", username, reason)
        return {
            "code": RADIUS_ACCESS_REJECT,
            "vlan": None,
            "attributes": {},
            "username": username,
            "reason": reason,
        }

    # ── Statistiques ──────────────────────────────────────────────────

    def active_sessions_count(self) -> int:
        """Retourne le nombre de sessions EAP en cours."""
        return len(self._sessions)

    def get_stats(self) -> dict:
        """Retourne les statistiques du serveur depuis le journal d'audit."""
        return self.audit_logger.count()
