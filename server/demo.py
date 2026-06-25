"""
demo.py — Script de démonstration interactif de Yahtou
Simule des machines se connectant au réseau via le serveur RADIUS.

Ce script illustre le flux complet d'authentification 802.1X :
    - Authentification réussie d'un employé (VLAN 10)
    - Authentification d'un invité (VLAN 20)
    - Rejet d'un mot de passe incorrect
    - Mise en quarantaine d'une machine suspecte (VLAN 99)
    - Blocage d'une adresse MAC
    - Vérification de l'intégrité du journal d'audit

Usage :
    python3 demo.py
"""

import os
import sys
import time
import logging

# Réduire le bruit des logs pour un affichage de démo épuré.
# Les logs INFO des modules sont masqués ; seul l'affichage de la démo reste.
logging.disable(logging.INFO)

# Import des modules Yahtou
from audit_logger import AuditLogger
from auth_backend import AuthBackend
from policy_engine import PolicyEngine
from radius_server import (
    RadiusServer,
    RADIUS_ACCESS_ACCEPT,
    RADIUS_ACCESS_REJECT,
)

# ── Couleurs ANSI pour un affichage lisible ───────────────────────────
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"


def banner(text):
    """Affiche un titre encadré."""
    line = "═" * 64
    print(f"\n{BLUE}{line}{RESET}")
    print(f"{BLUE}{BOLD}  {text}{RESET}")
    print(f"{BLUE}{line}{RESET}\n")


def pause(seconds=1.2):
    """Petite pause pour le rythme de la démo."""
    time.sleep(seconds)


def print_request(username, mac, password):
    """Affiche une demande d'accès entrante."""
    print(f"{DIM}┌─ Nouvelle demande d'accès au réseau{RESET}")
    print(f"{DIM}│{RESET}  Identité    : {BOLD}{username}{RESET}")
    print(f"{DIM}│{RESET}  Adresse MAC : {mac}")
    print(f"{DIM}│{RESET}  Mot de passe: {'•' * len(password)}")
    print(f"{DIM}└─ Transmission au serveur RADIUS Yahtou...{RESET}")
    pause(0.8)


def print_response(resp):
    """Affiche la réponse du serveur."""
    if resp["code"] == RADIUS_ACCESS_ACCEPT:
        vlan = resp["vlan"]
        print(f"   {GREEN}{BOLD}✓ ACCESS-ACCEPT{RESET}{GREEN} — Accès autorisé{RESET}")
        print(f"   {GREEN}→ Machine assignée au VLAN {vlan}{RESET}")
        if resp.get("attributes"):
            attrs = resp["attributes"]
            print(f"   {DIM}  Attributs RADIUS : Tunnel-Type={attrs.get('Tunnel-Type')}, "
                  f"VLAN={attrs.get('Tunnel-Private-Group-ID')}{RESET}")
    else:
        print(f"   {RED}{BOLD}✗ ACCESS-REJECT{RESET}{RED} — Accès refusé{RESET}")
        if resp.get("reason"):
            print(f"   {RED}→ Motif : {resp['reason']}{RESET}")
    pause()


def setup():
    """Initialise le serveur RADIUS et les données de démonstration."""
    # Bases de données de démo (réinitialisées à chaque lancement)
    base = os.path.dirname(os.path.abspath(__file__))
    db_dir = os.path.join(base, "..", "database")
    os.makedirs(db_dir, exist_ok=True)

    auth_db = os.path.join(db_dir, "demo_users.db")
    audit_db = os.path.join(db_dir, "demo_audit.db")
    schema = os.path.join(db_dir, "schema.sql")

    # Nettoyage des bases précédentes
    for path in (auth_db, audit_db):
        if os.path.exists(path):
            os.remove(path)

    auth = AuthBackend(db_path=auth_db, schema_path=schema)
    policy = PolicyEngine()
    audit = AuditLogger(db_path=audit_db)

    # Création des comptes de démonstration
    auth.create_user("eliel", "Yahtou2026!", "employe")
    auth.create_user("amadou", "Secure456!", "employe")
    auth.create_user("visiteur", "GuestPass!", "invite")
    auth.create_user("machine-suspecte", "weak", "quarantaine")

    server = RadiusServer(
        auth_backend=auth,
        policy_engine=policy,
        audit_logger=audit,
        shared_secret="yahtou-radius-secret-2026",
    )
    return server


def run_scenario(server):
    """Déroule le scénario de démonstration."""

    banner("YAHTOU — Démonstration du système d'authentification 802.1X")
    print("Le serveur RADIUS Yahtou est démarré et prêt à recevoir des demandes.")
    print(f"{DIM}Quatre comptes sont enregistrés : eliel, amadou (employés), "
          f"visiteur (invité), machine-suspecte (quarantaine).{RESET}")
    pause(2)

    # ── Scénario 1 : Employé légitime ─────────────────────────────────
    banner("Scénario 1 — Un employé se connecte au réseau")
    print_request("eliel", "AA:BB:CC:11:22:33", "Yahtou2026!")
    resp = server.handle_access_request(
        "demo-1", "eliel", "Yahtou2026!", "AA:BB:CC:11:22:33", "192.168.1.10"
    )
    print_response(resp)

    # ── Scénario 2 : Invité ───────────────────────────────────────────
    banner("Scénario 2 — Un visiteur se connecte (accès invité)")
    print_request("visiteur", "DD:EE:FF:44:55:66", "GuestPass!")
    resp = server.handle_access_request(
        "demo-2", "visiteur", "GuestPass!", "DD:EE:FF:44:55:66", "192.168.1.10"
    )
    print_response(resp)

    # ── Scénario 3 : Mauvais mot de passe ─────────────────────────────
    banner("Scénario 3 — Tentative avec un mot de passe incorrect")
    print_request("eliel", "AA:BB:CC:11:22:33", "MauvaisMDP")
    resp = server.handle_access_request(
        "demo-3", "eliel", "MauvaisMDP", "AA:BB:CC:11:22:33", "192.168.1.10"
    )
    print_response(resp)

    # ── Scénario 4 : Machine inconnue ─────────────────────────────────
    banner("Scénario 4 — Une machine inconnue tente de se connecter")
    print_request("intrus", "13:37:13:37:13:37", "hack")
    resp = server.handle_access_request(
        "demo-4", "intrus", "hack", "13:37:13:37:13:37", "192.168.1.10"
    )
    print_response(resp)

    # ── Scénario 5 : Quarantaine ──────────────────────────────────────
    banner("Scénario 5 — Une machine non conforme (quarantaine)")
    print_request("machine-suspecte", "99:99:99:99:99:99", "weak")
    resp = server.handle_access_request(
        "demo-5", "machine-suspecte", "weak", "99:99:99:99:99:99", "192.168.1.10"
    )
    print_response(resp)

    # ── Scénario 6 : Blocage de MAC ───────────────────────────────────
    banner("Scénario 6 — Blocage administratif d'une adresse MAC")
    print(f"{YELLOW}L'administrateur bloque la MAC AA:BB:CC:11:22:33 "
          f"(poste d'eliel signalé compromis).{RESET}")
    server.policy_engine.block_mac("AA:BB:CC:11:22:33")
    pause()
    print(f"{DIM}eliel tente de se reconnecter avec ses identifiants valides...{RESET}\n")
    print_request("eliel", "AA:BB:CC:11:22:33", "Yahtou2026!")
    resp = server.handle_access_request(
        "demo-6", "eliel", "Yahtou2026!", "AA:BB:CC:11:22:33", "192.168.1.10"
    )
    print_response(resp)
    print(f"{YELLOW}→ Bien que ses identifiants soient corrects, la machine est "
          f"placée en quarantaine (VLAN 99).{RESET}")
    pause(1.5)

    # ── Bilan : Journal d'audit ───────────────────────────────────────
    banner("Bilan — Journal d'audit et vérification d'intégrité")
    stats = server.get_stats()
    print(f"  Total des tentatives : {BOLD}{stats['total']}{RESET}")
    print(f"  {GREEN}Accès autorisés    : {stats['accepts']}{RESET}")
    print(f"  {RED}Accès refusés      : {stats['rejects']}{RESET}")
    pause()

    print(f"\n{DIM}Vérification de l'intégrité du journal (chaînage HMAC-SHA256)...{RESET}")
    pause()
    report = server.audit_logger.verify_integrity()
    if report["valid"]:
        print(f"  {GREEN}{BOLD}✓ Journal intègre{RESET}{GREEN} — "
              f"{report['total']} entrées vérifiées, aucune falsification.{RESET}")
    else:
        print(f"  {RED}{BOLD}⚠ Falsification détectée{RESET}{RED} — "
              f"entrées corrompues : {report['corrupted']}{RESET}")

    banner("Fin de la démonstration")
    print(f"{DIM}Le portail d'administration permet de consulter ces journaux "
          f"et de gérer les utilisateurs via une interface web sécurisée.{RESET}\n")


if __name__ == "__main__":
    try:
        radius = setup()
        run_scenario(radius)
    except KeyboardInterrupt:
        print(f"\n{YELLOW}Démonstration interrompue.{RESET}")
        sys.exit(0)
