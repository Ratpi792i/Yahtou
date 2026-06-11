"""
audit_logger.py — Module de journalisation infalsifiable pour Yahtou
Implémente un journal d'audit sécurisé avec chaînage HMAC-SHA256.

Chaque entrée est signée par :
    HMAC(clé_serveur, id || timestamp || identity || mac || ip_nas || result || vlan || hmac_précédent)

Toute modification d'une entrée invalide toutes les entrées suivantes.
"""

import hashlib
import hmac
import json
import logging
import os
import sqlite3
from datetime import datetime, timezone
from typing import Optional

# ── Configuration du logger système ──────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("yahtou.audit")


class AuditLogger:
    """
    Gestionnaire de journalisation infalsifiable.
    Les entrées sont chaînées par HMAC-SHA256 pour garantir l'intégrité.
    """

    DB_SCHEMA = """
        CREATE TABLE IF NOT EXISTS audit_log (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp   TEXT    NOT NULL,
            identity    TEXT    NOT NULL,
            mac_address TEXT    NOT NULL,
            ip_nas      TEXT    NOT NULL,
            result      TEXT    NOT NULL,
            vlan        TEXT,
            hmac        TEXT    NOT NULL
        );
    """

    def __init__(self, db_path: str, hmac_key: Optional[bytes] = None):
        """
        Initialise le logger d'audit.

        Args:
            db_path:  Chemin vers la base SQLite.
            hmac_key: Clé HMAC (32 octets recommandés). Si None, générée automatiquement.
        """
        self.db_path = db_path
        self.hmac_key = hmac_key or self._load_or_generate_key()
        self._init_db()
        logger.info("AuditLogger initialisé — base : %s", db_path)

    # ── Initialisation ────────────────────────────────────────────────

    def _load_or_generate_key(self) -> bytes:
        """Charge la clé HMAC depuis l'environnement ou en génère une nouvelle."""
        key_hex = os.environ.get("YAHTOU_HMAC_KEY")
        if key_hex:
            try:
                key = bytes.fromhex(key_hex)
                logger.info("Clé HMAC chargée depuis l'environnement.")
                return key
            except ValueError:
                logger.warning("YAHTOU_HMAC_KEY invalide, génération d'une nouvelle clé.")

        key = os.urandom(32)
        logger.warning(
            "Aucune clé HMAC configurée. Clé générée : %s\n"
            "Définissez YAHTOU_HMAC_KEY=%s dans l'environnement pour la persistance.",
            key.hex(), key.hex()
        )
        return key

    def _init_db(self) -> None:
        """Crée la table d'audit si elle n'existe pas."""
        with self._connect() as conn:
            conn.execute(self.DB_SCHEMA)

    def _connect(self) -> sqlite3.Connection:
        """Retourne une connexion SQLite."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    # ── Chaînage HMAC ─────────────────────────────────────────────────

    def _get_last_hmac(self, conn: sqlite3.Connection) -> str:
        """Récupère le HMAC de la dernière entrée (ou 'GENESIS' si vide)."""
        row = conn.execute(
            "SELECT hmac FROM audit_log ORDER BY id DESC LIMIT 1"
        ).fetchone()
        return row["hmac"] if row else "GENESIS"

    def _compute_hmac(
        self,
        entry_id: int,
        timestamp: str,
        identity: str,
        mac_address: str,
        ip_nas: str,
        result: str,
        vlan: str,
        previous_hmac: str,
    ) -> str:
        """
        Calcule le HMAC-SHA256 d'une entrée.

        Le message signé est la concaténation de tous les champs séparés par '|'.
        """
        message = "|".join([
            str(entry_id),
            timestamp,
            identity,
            mac_address,
            ip_nas,
            result,
            vlan or "",
            previous_hmac,
        ]).encode("utf-8")

        return hmac.new(self.hmac_key, message, hashlib.sha256).hexdigest()

    # ── Journalisation ────────────────────────────────────────────────

    def log(
        self,
        identity: str,
        mac_address: str,
        ip_nas: str,
        result: str,
        vlan: Optional[str] = None,
    ) -> int:
        """
        Enregistre un événement d'authentification dans le journal.

        Args:
            identity:    Identité soumise par le supplicant.
            mac_address: Adresse MAC de la machine cliente.
            ip_nas:      Adresse IP du commutateur (NAS).
            result:      Résultat : "ACCEPT" ou "REJECT".
            vlan:        VLAN assigné (uniquement si ACCEPT).

        Returns:
            L'identifiant de l'entrée créée.
        """
        if result not in ("ACCEPT", "REJECT"):
            raise ValueError(f"Résultat invalide : '{result}'. Attendu : ACCEPT ou REJECT.")

        timestamp = datetime.now(timezone.utc).isoformat()

        with self._connect() as conn:
            previous_hmac = self._get_last_hmac(conn)

            # Insertion provisoire pour obtenir l'ID auto-incrémenté
            cursor = conn.execute(
                """
                INSERT INTO audit_log (timestamp, identity, mac_address, ip_nas, result, vlan, hmac)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (timestamp, identity, mac_address, ip_nas, result, vlan, "PENDING")
            )
            entry_id = cursor.lastrowid

            # Calcul du HMAC avec l'ID définitif
            entry_hmac = self._compute_hmac(
                entry_id, timestamp, identity, mac_address,
                ip_nas, result, vlan or "", previous_hmac
            )

            # Mise à jour avec le HMAC définitif
            conn.execute(
                "UPDATE audit_log SET hmac = ? WHERE id = ?",
                (entry_hmac, entry_id)
            )

        logger.info(
            "Audit [%s] identity=%s mac=%s nas=%s vlan=%s",
            result, identity, mac_address, ip_nas, vlan or "-"
        )
        return entry_id

    # ── Vérification de l'intégrité ──────────────────────────────────

    def verify_integrity(self) -> dict:
        """
        Vérifie l'intégrité de l'ensemble du journal d'audit.

        Parcourt toutes les entrées dans l'ordre et recompute chaque HMAC.
        Retourne un rapport détaillé.

        Returns:
            dict avec les clés :
                - valid (bool)      : True si le journal est intact.
                - total (int)       : Nombre total d'entrées.
                - corrupted (list)  : Liste des IDs corrompus.
                - message (str)     : Message de synthèse.
        """
        corrupted = []
        previous_hmac = "GENESIS"

        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM audit_log ORDER BY id ASC"
            ).fetchall()

        for row in rows:
            expected_hmac = self._compute_hmac(
                row["id"],
                row["timestamp"],
                row["identity"],
                row["mac_address"],
                row["ip_nas"],
                row["result"],
                row["vlan"] or "",
                previous_hmac,
            )

            if not hmac.compare_digest(expected_hmac, row["hmac"]):
                corrupted.append(row["id"])
                logger.warning("Entrée corrompue détectée : id=%d", row["id"])

            previous_hmac = row["hmac"]

        valid = len(corrupted) == 0
        report = {
            "valid": valid,
            "total": len(rows),
            "corrupted": corrupted,
            "message": (
                f"Journal intact — {len(rows)} entrée(s) vérifiée(s)."
                if valid
                else f"ALERTE : {len(corrupted)} entrée(s) corrompue(s) détectée(s) : {corrupted}"
            )
        }

        if valid:
            logger.info(report["message"])
        else:
            logger.error(report["message"])

        return report

    # ── Consultation ──────────────────────────────────────────────────

    def get_logs(
        self,
        limit: int = 100,
        identity: Optional[str] = None,
        result: Optional[str] = None,
        since: Optional[str] = None,
    ) -> list:
        """
        Récupère les entrées du journal avec filtrage optionnel.

        Args:
            limit:    Nombre maximum d'entrées retournées.
            identity: Filtrer par identité (correspondance exacte).
            result:   Filtrer par résultat ("ACCEPT" ou "REJECT").
            since:    Filtrer les entrées depuis cette date ISO 8601.

        Returns:
            Liste de dict représentant les entrées (sans le champ hmac).
        """
        query = "SELECT id, timestamp, identity, mac_address, ip_nas, result, vlan FROM audit_log WHERE 1=1"
        params = []

        if identity:
            query += " AND identity = ?"
            params.append(identity)
        if result:
            query += " AND result = ?"
            params.append(result)
        if since:
            query += " AND timestamp >= ?"
            params.append(since)

        query += " ORDER BY id DESC LIMIT ?"
        params.append(limit)

        with self._connect() as conn:
            rows = conn.execute(query, params).fetchall()

        return [dict(row) for row in rows]

    def count(self) -> dict:
        """Retourne les statistiques basiques du journal."""
        with self._connect() as conn:
            total   = conn.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0]
            accepts = conn.execute("SELECT COUNT(*) FROM audit_log WHERE result='ACCEPT'").fetchone()[0]
            rejects = conn.execute("SELECT COUNT(*) FROM audit_log WHERE result='REJECT'").fetchone()[0]

        return {"total": total, "accepts": accepts, "rejects": rejects}

    def export_json(self, filepath: str) -> None:
        """Exporte le journal complet en JSON (sans les champs HMAC)."""
        logs = self.get_logs(limit=100000)
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(logs, f, indent=2, ensure_ascii=False)
        logger.info("Journal exporté vers %s (%d entrées)", filepath, len(logs))
