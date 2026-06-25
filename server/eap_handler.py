"""
eap_handler.py — Gestionnaire de la machine à états EAP-PEAP (Yahtou)
Orchestre le flux d'authentification EAP-PEAP entre le supplicant et le serveur.

Le protocole EAP-PEAP se déroule en deux phases :
    Phase 1 : établissement du tunnel TLS (via tls_session).
    Phase 2 : authentification MSCHAPv2 à l'intérieur du tunnel.

Ce module implémente la machine à états qui enchaîne :
    IDENTITY -> TLS_START -> TLS_HANDSHAKE -> MSCHAPV2 -> SUCCESS / FAILURE
"""

import logging
import os
from typing import Callable, Optional

from tls_session import TLSTunnel

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("yahtou.eap")


# Codes EAP (RFC 3748)
EAP_REQUEST = 1
EAP_RESPONSE = 2
EAP_SUCCESS = 3
EAP_FAILURE = 4

# Types EAP
EAP_TYPE_IDENTITY = 1
EAP_TYPE_PEAP = 25
EAP_TYPE_MSCHAPV2 = 26


class EAPError(Exception):
    """Levée lors d'une erreur dans le déroulement du protocole EAP."""


class EAPHandler:
    """
    Gestionnaire de la machine à états EAP-PEAP pour une session.

    Chaque instance gère une session d'authentification du début (Identity)
    à la fin (Success ou Failure).
    """

    # États de la machine EAP-PEAP
    STATE_IDLE = "IDLE"
    STATE_IDENTITY = "IDENTITY"
    STATE_TLS_START = "TLS_START"
    STATE_TLS_HANDSHAKE = "TLS_HANDSHAKE"
    STATE_MSCHAPV2 = "MSCHAPV2"
    STATE_SUCCESS = "SUCCESS"
    STATE_FAILURE = "FAILURE"

    # Transitions autorisées entre états
    TRANSITIONS = {
        STATE_IDLE: [STATE_IDENTITY, STATE_FAILURE],
        STATE_IDENTITY: [STATE_TLS_START, STATE_FAILURE],
        STATE_TLS_START: [STATE_TLS_HANDSHAKE, STATE_FAILURE],
        STATE_TLS_HANDSHAKE: [STATE_MSCHAPV2, STATE_FAILURE],
        STATE_MSCHAPV2: [STATE_SUCCESS, STATE_FAILURE],
        STATE_SUCCESS: [],
        STATE_FAILURE: [],
    }

    def __init__(self, session_id: str, auth_callback: Optional[Callable] = None):
        """
        Initialise le gestionnaire EAP pour une session.

        Args:
            session_id:    Identifiant unique de la session.
            auth_callback: Fonction appelée pour valider les credentials MSCHAPv2.
                           Signature : callback(username, password) -> dict | None.
        """
        self.session_id = session_id
        self.auth_callback = auth_callback
        self.state = self.STATE_IDLE
        self.identity: Optional[str] = None
        self.tunnel = TLSTunnel(session_id=session_id)
        self.auth_result: Optional[dict] = None
        logger.info("EAPHandler initialisé pour la session %s", session_id)

    # ── Gestion des transitions ───────────────────────────────────────

    def _transition(self, new_state: str) -> None:
        """Effectue une transition d'état en vérifiant qu'elle est autorisée."""
        allowed = self.TRANSITIONS.get(self.state, [])
        if new_state not in allowed:
            raise EAPError(
                f"Transition interdite : {self.state} -> {new_state} "
                f"(session {self.session_id})"
            )
        logger.info("EAP %s : %s -> %s", self.session_id, self.state, new_state)
        self.state = new_state

    # ── Phase d'identité ──────────────────────────────────────────────

    def handle_identity(self, identity: str) -> dict:
        """
        Traite la réponse EAP-Identity du supplicant.

        Args:
            identity: Identité annoncée par le supplicant.

        Returns:
            Un dict décrivant la prochaine requête EAP (TLS-Start).
        """
        if not identity:
            self._transition(self.STATE_FAILURE)
            raise EAPError("Identité vide reçue.")

        self._transition(self.STATE_IDENTITY)
        self.identity = identity
        logger.info("Identité reçue : %s (session %s)", identity, self.session_id)

        # On enchaîne immédiatement sur le démarrage du tunnel TLS
        return self.start_tls()

    # ── Phase 1 : Tunnel TLS ──────────────────────────────────────────

    def start_tls(self) -> dict:
        """
        Démarre la phase TLS (envoi du EAP-Request/PEAP-Start).

        Returns:
            Un dict décrivant la requête TLS-Start.
        """
        self._transition(self.STATE_TLS_START)
        self.tunnel.start_handshake()
        logger.info("Démarrage TLS pour la session %s", self.session_id)
        return {
            "code": EAP_REQUEST,
            "type": EAP_TYPE_PEAP,
            "phase": "tls_start",
            "session_id": self.session_id,
        }

    def handle_tls_handshake(self) -> dict:
        """
        Traite le handshake TLS et établit le tunnel.

        Returns:
            Un dict indiquant que le tunnel est prêt pour la Phase 2.
        """
        self._transition(self.STATE_TLS_HANDSHAKE)
        self.tunnel.complete_handshake()

        if not self.tunnel.is_established():
            self._transition(self.STATE_FAILURE)
            raise EAPError("Échec de l'établissement du tunnel TLS.")

        logger.info("Tunnel TLS établi pour la session %s", self.session_id)
        return {
            "code": EAP_REQUEST,
            "type": EAP_TYPE_PEAP,
            "phase": "tls_established",
            "tunnel_ready": True,
        }

    # ── Phase 2 : MSCHAPv2 dans le tunnel ─────────────────────────────

    def handle_mschapv2(self, username: str, password: str) -> dict:
        """
        Traite l'authentification MSCHAPv2 à l'intérieur du tunnel TLS.

        Args:
            username: Nom d'utilisateur transmis dans le tunnel.
            password: Mot de passe transmis dans le tunnel.

        Returns:
            Un dict décrivant le résultat final (Success ou Failure).
        """
        if not self.tunnel.is_established():
            raise EAPError("MSCHAPv2 impossible : tunnel TLS non établi.")

        self._transition(self.STATE_MSCHAPV2)
        logger.info("Authentification MSCHAPv2 pour %s (session %s)",
                    username, self.session_id)

        # Validation via le callback (typiquement AuthBackend.authenticate)
        if self.auth_callback is None:
            self._transition(self.STATE_FAILURE)
            raise EAPError("Aucun callback d'authentification configuré.")

        try:
            result = self.auth_callback(username, password)
        except Exception as exc:  # pylint: disable=broad-except
            logger.info("Échec MSCHAPv2 pour %s : %s", username, exc)
            result = None

        if result:
            self.auth_result = result
            return self._build_success()
        return self._build_failure()

    # ── Résultats finaux ──────────────────────────────────────────────

    def _build_success(self) -> dict:
        """Construit la réponse EAP-Success."""
        self._transition(self.STATE_SUCCESS)
        self.tunnel.close()
        logger.info("EAP-Success pour la session %s", self.session_id)
        return {
            "code": EAP_SUCCESS,
            "session_id": self.session_id,
            "identity": self.identity,
            "auth_result": self.auth_result,
        }

    def _build_failure(self) -> dict:
        """Construit la réponse EAP-Failure."""
        self._transition(self.STATE_FAILURE)
        self.tunnel.close()
        logger.info("EAP-Failure pour la session %s", self.session_id)
        return {
            "code": EAP_FAILURE,
            "session_id": self.session_id,
            "identity": self.identity,
        }

    # ── Utilitaires ───────────────────────────────────────────────────

    def is_complete(self) -> bool:
        """Indique si la session EAP est terminée (succès ou échec)."""
        return self.state in (self.STATE_SUCCESS, self.STATE_FAILURE)

    def is_successful(self) -> bool:
        """Indique si la session EAP s'est terminée avec succès."""
        return self.state == self.STATE_SUCCESS

    def reset(self) -> None:
        """Réinitialise la machine à états pour une nouvelle tentative."""
        self.state = self.STATE_IDLE
        self.identity = None
        self.auth_result = None
        self.tunnel = TLSTunnel(session_id=self.session_id)
        logger.info("EAPHandler réinitialisé pour la session %s", self.session_id)

    def __repr__(self) -> str:
        return f"<EAPHandler session={self.session_id} state={self.state}>"
