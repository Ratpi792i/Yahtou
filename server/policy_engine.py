"""
policy_engine.py — Moteur de politique d'attribution des VLANs pour Yahtou
Détermine le VLAN à assigner à une machine selon son rôle et les politiques en vigueur.

Responsabilités :
    - Traduire un rôle authentifié en attributs RADIUS de VLAN (64/65/81).
    - Appliquer des politiques contextuelles (heure, quarantaine forcée).
    - Fournir une décision d'autorisation finale au serveur RADIUS.
"""

import logging
from typing import Optional

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("yahtou.policy")


# Attributs RADIUS standard pour l'attribution dynamique de VLAN (RFC 3580)
TUNNEL_TYPE_VLAN = 13          # Attribut 64 : Tunnel-Type = VLAN
TUNNEL_MEDIUM_IEEE_802 = 6     # Attribut 65 : Tunnel-Medium-Type = IEEE 802

# VLAN de quarantaine par défaut (machine non conforme ou suspecte)
QUARANTINE_VLAN = "99"


class PolicyDecision:
    """
    Représente une décision de politique d'accès.
    Contient le résultat (ACCEPT/REJECT) et les attributs VLAN associés.
    """

    def __init__(self, accept: bool, vlan_id: Optional[str] = None, reason: str = ""):
        self.accept = accept
        self.vlan_id = vlan_id
        self.reason = reason

    def to_radius_attributes(self) -> dict:
        """
        Convertit la décision en attributs RADIUS pour un Access-Accept.

        Returns:
            dict des attributs RADIUS (vide si REJECT).
        """
        if not self.accept or not self.vlan_id:
            return {}
        return {
            "Tunnel-Type": TUNNEL_TYPE_VLAN,
            "Tunnel-Medium-Type": TUNNEL_MEDIUM_IEEE_802,
            "Tunnel-Private-Group-ID": self.vlan_id,
        }

    def __repr__(self) -> str:
        statut = "ACCEPT" if self.accept else "REJECT"
        return f"<PolicyDecision {statut} vlan={self.vlan_id} reason='{self.reason}'>"


class PolicyEngine:
    """
    Moteur de décision d'autorisation de Yahtou.
    Prend une identité authentifiée et retourne une décision d'accès avec VLAN.
    """

    def __init__(self, quarantine_vlan: str = QUARANTINE_VLAN):
        """
        Initialise le moteur de politique.

        Args:
            quarantine_vlan: VLAN vers lequel rediriger les machines suspectes.
        """
        self.quarantine_vlan = quarantine_vlan
        self._blocked_macs = set()
        logger.info("PolicyEngine initialisé (VLAN quarantaine : %s)", quarantine_vlan)

    # ── Gestion de la liste de blocage ────────────────────────────────

    def block_mac(self, mac_address: str) -> None:
        """Ajoute une adresse MAC à la liste de blocage (quarantaine forcée)."""
        self._blocked_macs.add(mac_address.upper())
        logger.info("Adresse MAC bloquée : %s", mac_address)

    def unblock_mac(self, mac_address: str) -> None:
        """Retire une adresse MAC de la liste de blocage."""
        self._blocked_macs.discard(mac_address.upper())
        logger.info("Adresse MAC débloquée : %s", mac_address)

    def is_blocked(self, mac_address: str) -> bool:
        """Vérifie si une adresse MAC est dans la liste de blocage."""
        return mac_address.upper() in self._blocked_macs

    # ── Décision d'autorisation ───────────────────────────────────────

    def evaluate(
        self,
        auth_result: Optional[dict],
        mac_address: str,
    ) -> PolicyDecision:
        """
        Évalue la politique d'accès pour une machine authentifiée.

        Args:
            auth_result: Résultat de AuthBackend.authenticate(), ou None si échec.
                         Doit contenir 'username', 'role', 'vlan_id'.
            mac_address: Adresse MAC de la machine cliente.

        Returns:
            Une PolicyDecision indiquant l'acceptation et le VLAN.
        """
        # 1. Échec d'authentification → rejet
        if auth_result is None:
            logger.info("Décision : REJECT (authentification échouée) mac=%s", mac_address)
            return PolicyDecision(
                accept=False,
                reason="Authentification échouée"
            )

        # 2. Machine sur liste de blocage → quarantaine forcée
        if self.is_blocked(mac_address):
            logger.info(
                "Décision : ACCEPT->quarantaine (MAC bloquée) user=%s mac=%s",
                auth_result.get("username"), mac_address
            )
            return PolicyDecision(
                accept=True,
                vlan_id=self.quarantine_vlan,
                reason="Adresse MAC sur liste de blocage"
            )

        # 3. Rôle quarantaine → VLAN quarantaine
        role = auth_result.get("role")
        vlan_id = auth_result.get("vlan_id")

        if role == "quarantaine":
            logger.info(
                "Décision : ACCEPT->quarantaine (rôle) user=%s",
                auth_result.get("username")
            )
            return PolicyDecision(
                accept=True,
                vlan_id=self.quarantine_vlan,
                reason="Rôle quarantaine"
            )

        # 4. Cas nominal → VLAN du rôle
        if not vlan_id:
            logger.warning(
                "Aucun VLAN associé au rôle '%s', redirection quarantaine.", role
            )
            return PolicyDecision(
                accept=True,
                vlan_id=self.quarantine_vlan,
                reason="VLAN manquant pour le rôle"
            )

        logger.info(
            "Décision : ACCEPT user=%s role=%s vlan=%s",
            auth_result.get("username"), role, vlan_id
        )
        return PolicyDecision(
            accept=True,
            vlan_id=vlan_id,
            reason=f"Accès autorisé (rôle {role})"
        )
