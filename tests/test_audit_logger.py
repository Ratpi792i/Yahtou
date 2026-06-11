"""
test_audit_logger.py — Tests unitaires pour audit_logger.py
Couverture : initialisation, journalisation, intégrité, filtrage, export.
"""

import json
import os
import tempfile

import pytest

from audit_logger import AuditLogger


# ── Fixtures ─────────────────────────────────────────────────────────

@pytest.fixture
def logger_instance():
    """Crée un AuditLogger temporaire pour chaque test."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name
    key = os.urandom(32)
    audit = AuditLogger(db_path=db_path, hmac_key=key)
    yield audit
    os.unlink(db_path)


# ── Tests d'initialisation ────────────────────────────────────────────

class TestInitialisation:

    def test_db_cree(self, logger_instance):
        """La base de données doit être créée au démarrage."""
        assert os.path.exists(logger_instance.db_path)

    def test_journal_vide_au_depart(self, logger_instance):
        """Un journal vide doit avoir zéro entrée."""
        stats = logger_instance.count()
        assert stats["total"] == 0
        assert stats["accepts"] == 0
        assert stats["rejects"] == 0

    def test_integrite_journal_vide(self, logger_instance):
        """L'intégrité d'un journal vide doit être valide."""
        report = logger_instance.verify_integrity()
        assert report["valid"] is True
        assert report["total"] == 0
        assert report["corrupted"] == []


# ── Tests de journalisation ───────────────────────────────────────────

class TestJournalisation:

    def test_log_accept(self, logger_instance):
        """Un ACCEPT doit être enregistré correctement."""
        entry_id = logger_instance.log(
            identity="eliel@yahtou.local",
            mac_address="AA:BB:CC:DD:EE:FF",
            ip_nas="192.168.1.1",
            result="ACCEPT",
            vlan="10"
        )
        assert entry_id == 1
        stats = logger_instance.count()
        assert stats["accepts"] == 1
        assert stats["rejects"] == 0

    def test_log_reject(self, logger_instance):
        """Un REJECT doit être enregistré correctement."""
        entry_id = logger_instance.log(
            identity="inconnu@yahtou.local",
            mac_address="00:11:22:33:44:55",
            ip_nas="192.168.1.2",
            result="REJECT"
        )
        assert entry_id == 1
        stats = logger_instance.count()
        assert stats["rejects"] == 1

    def test_log_result_invalide(self, logger_instance):
        """Un résultat invalide doit lever une ValueError."""
        with pytest.raises(ValueError, match="Résultat invalide"):
            logger_instance.log(
                identity="test",
                mac_address="AA:BB:CC:DD:EE:FF",
                ip_nas="192.168.1.1",
                result="INVALID"
            )

    def test_log_multiple_entrees(self, logger_instance):
        """Plusieurs entrées doivent être correctement comptabilisées."""
        for i in range(5):
            logger_instance.log(
                identity=f"user{i}@yahtou.local",
                mac_address=f"AA:BB:CC:DD:EE:0{i}",
                ip_nas="192.168.1.1",
                result="ACCEPT",
                vlan="10"
            )
        logger_instance.log(
            identity="intrus@ext.com",
            mac_address="FF:FF:FF:FF:FF:FF",
            ip_nas="192.168.1.1",
            result="REJECT"
        )
        stats = logger_instance.count()
        assert stats["total"] == 6
        assert stats["accepts"] == 5
        assert stats["rejects"] == 1

    def test_ids_incrementaux(self, logger_instance):
        """Les IDs doivent être auto-incrémentaux."""
        id1 = logger_instance.log("u1", "AA:BB:CC:DD:EE:01", "192.168.1.1", "ACCEPT", "10")
        id2 = logger_instance.log("u2", "AA:BB:CC:DD:EE:02", "192.168.1.1", "REJECT")
        id3 = logger_instance.log("u3", "AA:BB:CC:DD:EE:03", "192.168.1.1", "ACCEPT", "20")
        assert id1 == 1
        assert id2 == 2
        assert id3 == 3


# ── Tests d'intégrité HMAC ────────────────────────────────────────────

class TestIntegrite:

    def test_integrite_apres_logs(self, logger_instance):
        """Le journal doit être intact après plusieurs insertions."""
        for i in range(10):
            logger_instance.log(
                identity=f"user{i}@yahtou.local",
                mac_address=f"AA:BB:CC:DD:EE:{i:02X}",
                ip_nas="192.168.1.1",
                result="ACCEPT",
                vlan="10"
            )
        report = logger_instance.verify_integrity()
        assert report["valid"] is True
        assert report["total"] == 10
        assert report["corrupted"] == []

    def test_falsification_detectee(self, logger_instance):
        """Toute modification directe de la base doit être détectée."""
        import sqlite3
        logger_instance.log("user@yahtou.local", "AA:BB:CC:DD:EE:FF", "192.168.1.1", "ACCEPT", "10")
        logger_instance.log("user2@yahtou.local", "AA:BB:CC:DD:EE:01", "192.168.1.1", "REJECT")

        # Falsification directe
        conn = sqlite3.connect(logger_instance.db_path)
        conn.execute("UPDATE audit_log SET result='ACCEPT' WHERE id=2")
        conn.commit()
        conn.close()

        report = logger_instance.verify_integrity()
        assert report["valid"] is False
        assert 2 in report["corrupted"]

    def test_falsification_premiere_entree(self, logger_instance):
        """La modification de la première entrée doit invalider toutes les suivantes."""
        import sqlite3
        for i in range(5):
            logger_instance.log(f"user{i}", f"AA:BB:CC:DD:EE:0{i}", "192.168.1.1", "ACCEPT", "10")

        # Modifier la première entrée
        conn = sqlite3.connect(logger_instance.db_path)
        conn.execute("UPDATE audit_log SET identity='attaquant' WHERE id=1")
        conn.commit()
        conn.close()

        report = logger_instance.verify_integrity()
        assert report["valid"] is False
        # Toutes les entrées à partir de l'id 1 doivent être marquées corrompues
        assert len(report["corrupted"]) >= 1

    def test_cles_differentes_invalident(self, logger_instance):
        """Un journal créé avec une clé différente doit être invalide."""
        logger_instance.log("user@yahtou.local", "AA:BB:CC:DD:EE:FF", "192.168.1.1", "ACCEPT", "10")

        # Créer un nouveau logger avec une clé différente sur la même DB
        autre_logger = AuditLogger(db_path=logger_instance.db_path, hmac_key=os.urandom(32))
        report = autre_logger.verify_integrity()
        assert report["valid"] is False


# ── Tests de consultation ─────────────────────────────────────────────

class TestConsultation:

    def test_get_logs_sans_filtre(self, logger_instance):
        """Sans filtre, get_logs doit retourner toutes les entrées."""
        for i in range(5):
            logger_instance.log(f"user{i}", f"AA:BB:CC:DD:EE:0{i}", "192.168.1.1", "ACCEPT", "10")
        logs = logger_instance.get_logs()
        assert len(logs) == 5

    def test_get_logs_filtre_result(self, logger_instance):
        """Le filtre par résultat doit fonctionner correctement."""
        logger_instance.log("u1", "AA:BB:CC:DD:EE:01", "192.168.1.1", "ACCEPT", "10")
        logger_instance.log("u2", "AA:BB:CC:DD:EE:02", "192.168.1.1", "REJECT")
        logger_instance.log("u3", "AA:BB:CC:DD:EE:03", "192.168.1.1", "ACCEPT", "20")

        accepts = logger_instance.get_logs(result="ACCEPT")
        rejects = logger_instance.get_logs(result="REJECT")
        assert len(accepts) == 2
        assert len(rejects) == 1

    def test_get_logs_filtre_identity(self, logger_instance):
        """Le filtre par identité doit retourner uniquement les entrées correspondantes."""
        logger_instance.log("eliel@yahtou.local", "AA:BB:CC:DD:EE:01", "192.168.1.1", "ACCEPT", "10")
        logger_instance.log("amadou@yahtou.local", "AA:BB:CC:DD:EE:02", "192.168.1.1", "ACCEPT", "10")
        logger_instance.log("eliel@yahtou.local", "AA:BB:CC:DD:EE:01", "192.168.1.1", "ACCEPT", "10")

        logs = logger_instance.get_logs(identity="eliel@yahtou.local")
        assert len(logs) == 2
        assert all(log["identity"] == "eliel@yahtou.local" for log in logs)

    def test_get_logs_limit(self, logger_instance):
        """Le paramètre limit doit être respecté."""
        for i in range(20):
            logger_instance.log(f"user{i}", f"AA:BB:CC:DD:EE:{i:02X}", "192.168.1.1", "ACCEPT", "10")
        logs = logger_instance.get_logs(limit=5)
        assert len(logs) == 5

    def test_logs_sans_hmac(self, logger_instance):
        """Les entrées retournées ne doivent pas contenir le champ hmac."""
        logger_instance.log("user", "AA:BB:CC:DD:EE:FF", "192.168.1.1", "ACCEPT", "10")
        logs = logger_instance.get_logs()
        assert len(logs) == 1
        assert "hmac" not in logs[0]


# ── Tests d'export ─────────────────────────────────────────────────────

class TestExport:

    def test_export_json(self, logger_instance, tmp_path):
        """L'export JSON doit produire un fichier valide."""
        logger_instance.log("user1", "AA:BB:CC:DD:EE:01", "192.168.1.1", "ACCEPT", "10")
        logger_instance.log("user2", "AA:BB:CC:DD:EE:02", "192.168.1.1", "REJECT")

        export_path = str(tmp_path / "export.json")
        logger_instance.export_json(export_path)

        assert os.path.exists(export_path)
        with open(export_path, encoding="utf-8") as f:
            data = json.load(f)

        assert len(data) == 2
        assert data[0]["identity"] in ("user1", "user2")
        assert "hmac" not in data[0]
