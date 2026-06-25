"""
app.py — Portail d'administration Flask pour Yahtou
Interface web sécurisée de gestion du système d'authentification.

Fonctionnalités :
    - Authentification administrateur (bcrypt + session).
    - Contrôle d'accès basé sur les rôles (super-admin, auditeur).
    - Gestion des utilisateurs (CRUD) et des rôles.
    - Consultation des journaux d'audit (lecture seule).
    - Blocage / déblocage des adresses MAC.

Sécurité :
    - Protection CSRF sur tous les formulaires (Flask-WTF).
    - Rate limiting sur la connexion.
    - Sessions signées, cookies HTTPOnly et Secure.
    - Mots de passe administrateur hachés avec bcrypt.
"""

import functools
import logging
import os
import sqlite3
import time
from datetime import datetime, timezone

import bcrypt
from flask import (
    Flask, render_template, request, redirect, url_for,
    session, flash, abort
)
from flask_wtf import CSRFProtect

from audit_logger import AuditLogger
from auth_backend import AuthBackend, AuthenticationError

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("yahtou.portal")


# ── Configuration des chemins ─────────────────────────────────────────
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "..", "database", "yahtou.db")
AUDIT_DB_PATH = os.path.join(BASE_DIR, "..", "database", "audit.db")
SCHEMA_PATH = os.path.join(BASE_DIR, "..", "database", "schema.sql")

# ── Rate limiting (mémoire) ───────────────────────────────────────────
_login_attempts = {}
MAX_ATTEMPTS = 5
WINDOW_SECONDS = 60


def create_app(test_config: dict = None) -> Flask:
    """
    Factory de l'application Flask.

    Args:
        test_config: Configuration optionnelle pour les tests.

    Returns:
        L'application Flask configurée.
    """
    app = Flask(__name__)

    # Clé secrète pour signer les sessions
    app.config["SECRET_KEY"] = os.environ.get(
        "YAHTOU_SECRET_KEY", os.urandom(32).hex()
    )
    # Cookies sécurisés
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
    # En production, activer Secure (HTTPS only)
    app.config["SESSION_COOKIE_SECURE"] = not (test_config or {}).get("TESTING", False)

    if test_config:
        app.config.update(test_config)

    # Protection CSRF
    csrf = CSRFProtect(app)

    # Backends
    db_path = app.config.get("DB_PATH", DB_PATH)
    audit_db_path = app.config.get("AUDIT_DB_PATH", AUDIT_DB_PATH)
    schema_path = app.config.get("SCHEMA_PATH", SCHEMA_PATH)

    auth_backend = AuthBackend(db_path=db_path, schema_path=schema_path)
    audit_logger = AuditLogger(db_path=audit_db_path)

    _ensure_admin_table(db_path)

    # ── Décorateurs de sécurité ──────────────────────────────────────

    def login_required(view):
        """Exige une session administrateur active."""
        @functools.wraps(view)
        def wrapped(*args, **kwargs):
            if "admin" not in session:
                return redirect(url_for("login"))
            return view(*args, **kwargs)
        return wrapped

    def super_admin_required(view):
        """Exige le rôle super-admin (modification interdite aux auditeurs)."""
        @functools.wraps(view)
        def wrapped(*args, **kwargs):
            if "admin" not in session:
                return redirect(url_for("login"))
            if session.get("role") != "super-admin":
                abort(403)
            return view(*args, **kwargs)
        return wrapped

    # ── Authentification ─────────────────────────────────────────────

    def _check_rate_limit(ip: str) -> bool:
        """Retourne True si l'IP n'a pas dépassé la limite de tentatives."""
        now = time.time()
        attempts = _login_attempts.get(ip, [])
        attempts = [t for t in attempts if now - t < WINDOW_SECONDS]
        _login_attempts[ip] = attempts
        return len(attempts) < MAX_ATTEMPTS

    def _record_attempt(ip: str) -> None:
        """Enregistre une tentative de connexion échouée."""
        _login_attempts.setdefault(ip, []).append(time.time())

    @app.route("/", methods=["GET"])
    def index():
        """Page d'accueil — redirige vers le tableau de bord ou la connexion."""
        if "admin" in session:
            return redirect(url_for("dashboard"))
        return redirect(url_for("login"))

    @app.route("/login", methods=["GET", "POST"])
    def login():
        """Page de connexion administrateur."""
        if request.method == "POST":
            ip = request.remote_addr or "unknown"

            if not _check_rate_limit(ip):
                flash("Trop de tentatives. Réessayez dans une minute.", "error")
                return render_template("login.html"), 429

            username = request.form.get("username", "")
            password = request.form.get("password", "")

            admin = _verify_admin(db_path, username, password)
            if admin:
                session.clear()
                session["admin"] = username
                session["role"] = admin["role"]
                logger.info("Connexion admin réussie : %s", username)
                return redirect(url_for("dashboard"))

            _record_attempt(ip)
            flash("Identifiants invalides.", "error")
            logger.info("Connexion admin échouée : %s", username)

        return render_template("login.html")

    @app.route("/logout")
    def logout():
        """Déconnexion."""
        session.clear()
        flash("Vous avez été déconnecté.", "success")
        return redirect(url_for("login"))

    # ── Tableau de bord ──────────────────────────────────────────────

    @app.route("/dashboard")
    @login_required
    def dashboard():
        """Tableau de bord principal avec statistiques."""
        users = auth_backend.list_users()
        stats = audit_logger.count()
        recent_logs = audit_logger.get_logs(limit=10)
        return render_template(
            "dashboard.html",
            users=users,
            stats=stats,
            recent_logs=recent_logs,
            role=session.get("role"),
        )

    # ── Gestion des utilisateurs ─────────────────────────────────────

    @app.route("/users")
    @login_required
    def users_list():
        """Liste des utilisateurs."""
        users = auth_backend.list_users()
        roles = auth_backend.list_roles()
        return render_template(
            "users.html", users=users, roles=roles, role=session.get("role")
        )

    @app.route("/users/create", methods=["POST"])
    @super_admin_required
    def users_create():
        """Création d'un utilisateur."""
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        role = request.form.get("role", "")
        try:
            auth_backend.create_user(username, password, role)
            flash(f"Utilisateur '{username}' créé.", "success")
        except ValueError as exc:
            flash(str(exc), "error")
        return redirect(url_for("users_list"))

    @app.route("/users/<username>/role", methods=["POST"])
    @super_admin_required
    def users_change_role(username):
        """Changement de rôle d'un utilisateur."""
        new_role = request.form.get("role", "")
        try:
            auth_backend.change_role(username, new_role)
            flash(f"Rôle de '{username}' modifié.", "success")
        except ValueError as exc:
            flash(str(exc), "error")
        return redirect(url_for("users_list"))

    @app.route("/users/<username>/toggle", methods=["POST"])
    @super_admin_required
    def users_toggle(username):
        """Active ou désactive un utilisateur."""
        user = auth_backend.get_user(username)
        if user:
            if user["active"]:
                auth_backend.deactivate_user(username)
                flash(f"'{username}' désactivé.", "success")
            else:
                auth_backend.activate_user(username)
                flash(f"'{username}' réactivé.", "success")
        return redirect(url_for("users_list"))

    @app.route("/users/<username>/delete", methods=["POST"])
    @super_admin_required
    def users_delete(username):
        """Supprime un utilisateur."""
        auth_backend.delete_user(username)
        flash(f"'{username}' supprimé.", "success")
        return redirect(url_for("users_list"))

    # ── Journaux d'audit ─────────────────────────────────────────────

    @app.route("/logs")
    @login_required
    def logs_view():
        """Consultation des journaux d'audit (lecture seule)."""
        result_filter = request.args.get("result")
        identity_filter = request.args.get("identity")
        logs = audit_logger.get_logs(
            limit=200,
            result=result_filter or None,
            identity=identity_filter or None,
        )
        integrity = audit_logger.verify_integrity()
        return render_template(
            "logs.html",
            logs=logs,
            integrity=integrity,
            role=session.get("role"),
        )

    # ── Gestion des erreurs ──────────────────────────────────────────

    @app.errorhandler(403)
    def forbidden(_):
        """Page 403 — accès interdit."""
        return render_template("error.html",
                               code=403,
                               message="Accès interdit. Droits insuffisants."), 403

    @app.errorhandler(404)
    def not_found(_):
        """Page 404 — non trouvé."""
        return render_template("error.html",
                               code=404,
                               message="Page introuvable."), 404

    return app


# ── Gestion de la table admins ────────────────────────────────────────

def _ensure_admin_table(db_path: str) -> None:
    """Crée la table admins et un compte par défaut si nécessaire."""
    conn = sqlite3.connect(db_path)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS admins (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            username      TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            role          TEXT NOT NULL DEFAULT 'super-admin',
            active        INTEGER NOT NULL DEFAULT 1,
            created_at    TEXT NOT NULL
        )
    """)
    # Compte admin par défaut (à changer en production)
    existing = conn.execute("SELECT id FROM admins LIMIT 1").fetchone()
    if not existing:
        default_pwd = os.environ.get("YAHTOU_ADMIN_PASSWORD", "admin123")
        pwd_hash = bcrypt.hashpw(
            default_pwd.encode("utf-8"), bcrypt.gensalt(rounds=12)
        ).decode("utf-8")
        conn.execute(
            "INSERT INTO admins (username, password_hash, role, created_at) "
            "VALUES (?, ?, ?, ?)",
            ("admin", pwd_hash, "super-admin", datetime.now(timezone.utc).isoformat())
        )
        logger.info("Compte admin par défaut créé (username=admin).")
    conn.commit()
    conn.close()


def _verify_admin(db_path: str, username: str, password: str):
    """Vérifie les credentials d'un administrateur."""
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    row = conn.execute(
        "SELECT username, password_hash, role, active FROM admins WHERE username = ?",
        (username,)
    ).fetchone()
    conn.close()

    if not row or not row["active"]:
        return None
    try:
        if bcrypt.checkpw(password.encode("utf-8"), row["password_hash"].encode("utf-8")):
            return {"username": row["username"], "role": row["role"]}
    except (ValueError, TypeError):
        return None
    return None


if __name__ == "__main__":
    application = create_app()
    # En production : utiliser un serveur WSGI (gunicorn) derrière HTTPS
    application.run(host="127.0.0.1", port=5000, debug=False)
