# Copyright 2025 Dubhe Srls
# License LGPL-3

import hmac
import secrets
from datetime import datetime, timedelta

from odoo import _, api, fields, models


class OAuth2AuthorizationCode(models.Model):
    _name = "oauth2.authorization_code"
    _description = "OAuth2 Authorization Code"
    _rec_name = "code"

    code = fields.Char(
        string="Authorization Code",
        required=True,
        readonly=True,
        default=lambda self: secrets.token_urlsafe(32),
        index=True,
    )
    client_id = fields.Many2one(
        "oauth2.client",
        string="Client",
        required=True,
        ondelete="cascade",
    )
    user_id = fields.Many2one(
        "res.users",
        string="User",
        required=True,
        ondelete="cascade",
    )
    redirect_uri = fields.Char(string="Redirect URI", required=True)
    scope = fields.Char(string="Scope")
    expires_at = fields.Datetime(string="Expires At", required=True)
    used = fields.Boolean(string="Used", default=False)

    # PKCE fields
    code_challenge = fields.Char(string="Code Challenge")
    code_challenge_method = fields.Selection([
        ("S256", "S256 (SHA-256)"),
    ], string="Code Challenge Method", default="S256")

    # State for CSRF protection
    state = fields.Char(string="State")

    def is_valid(self):
        """Check if authorization code is still valid"""
        self.ensure_one()
        if self.used:
            return False
        if fields.Datetime.now() > self.expires_at:
            return False
        return True

    def mark_used(self):
        """Mark authorization code as used"""
        self.ensure_one()
        self.write({"used": True})

    def mark_used_atomic(self):
        """
        Atomically mark authorization code as used.
        Returns True if successfully marked, False if already used.
        Prevents race conditions in token exchange.
        """
        self.ensure_one()
        # Use direct SQL for atomic update with condition
        query = """
            UPDATE oauth2_authorization_code
            SET used = TRUE
            WHERE id = %s AND used = FALSE
            RETURNING id
        """
        self.env.cr.execute(query, (self.id,))
        result = self.env.cr.fetchone()
        # Invalidate cache since we updated directly
        self.invalidate_recordset()
        return result is not None

    @api.model
    def cleanup_expired(self):
        """Remove expired authorization codes"""
        expired = self.search([
            "|",
            ("expires_at", "<", fields.Datetime.now()),
            ("used", "=", True),
        ])
        expired.unlink()
        return True

    @api.model
    def create_code(
        self, client, user, redirect_uri, scope=None,
        code_challenge=None, code_challenge_method="S256", state=None
    ):
        """Create a new authorization code"""
        # Codes valid for 10 minutes
        expires_at = datetime.now() + timedelta(minutes=10)
        return self.create({
            "client_id": client.id,
            "user_id": user.id,
            "redirect_uri": redirect_uri,
            "scope": scope,
            "expires_at": expires_at,
            "code_challenge": code_challenge,
            "code_challenge_method": code_challenge_method,
            "state": state,
        })


class OAuth2AccessToken(models.Model):
    _name = "oauth2.access_token"
    _description = "OAuth2 Access Token"
    _rec_name = "token_prefix"

    token = fields.Char(
        string="Access Token",
        required=True,
        readonly=True,
        index=True,
    )
    token_prefix = fields.Char(
        string="Token Prefix",
        compute="_compute_token_prefix",
        store=True,
    )
    token_type = fields.Selection([
        ("Bearer", "Bearer"),
    ], string="Token Type", default="Bearer", required=True)

    client_id = fields.Many2one(
        "oauth2.client",
        string="Client",
        required=True,
        ondelete="cascade",
    )
    user_id = fields.Many2one(
        "res.users",
        string="User",
        required=True,
        ondelete="cascade",
    )
    scope = fields.Char(string="Scope")
    expires_at = fields.Datetime(string="Expires At", required=True)
    revoked = fields.Boolean(string="Revoked", default=False)

    # Refresh token
    refresh_token = fields.Char(string="Refresh Token", index=True)
    refresh_expires_at = fields.Datetime(string="Refresh Token Expires At")

    # Audit
    created_at = fields.Datetime(
        string="Created At",
        default=fields.Datetime.now,
        readonly=True,
    )
    last_used_at = fields.Datetime(string="Last Used At")
    ip_address = fields.Char(string="IP Address")
    user_agent = fields.Char(string="User Agent")

    @api.depends("token")
    def _compute_token_prefix(self):
        for record in self:
            if record.token:
                record.token_prefix = record.token[:8] + "..."
            else:
                record.token_prefix = ""

    def is_valid(self):
        """Check if access token is still valid"""
        self.ensure_one()
        if self.revoked:
            return False
        if fields.Datetime.now() > self.expires_at:
            return False
        return True

    def is_refresh_valid(self):
        """Check if refresh token is still valid"""
        self.ensure_one()
        if self.revoked:
            return False
        if not self.refresh_token or not self.refresh_expires_at:
            return False
        if fields.Datetime.now() > self.refresh_expires_at:
            return False
        return True

    def revoke(self):
        """Revoke the access token"""
        self.write({"revoked": True})

    def update_last_used(self, ip_address=None):
        """Update last used timestamp using new cursor to handle read-only contexts."""
        self.ensure_one()
        try:
            # Use direct SQL with new cursor to avoid read-only transaction issues
            import odoo
            with odoo.registry(self.env.cr.dbname).cursor() as cr:
                now = fields.Datetime.now()
                if ip_address:
                    cr.execute(
                        "UPDATE oauth2_access_token SET last_used_at = %s, "
                        "ip_address = %s WHERE id = %s",
                        (now, ip_address, self.id)
                    )
                else:
                    cr.execute(
                        "UPDATE oauth2_access_token SET last_used_at = %s "
                        "WHERE id = %s",
                        (now, self.id)
                    )
        except Exception:
            # Silently ignore errors
            pass

    @api.model
    def cleanup_expired(self):
        """Remove expired and revoked tokens"""
        expired = self.search([
            "|",
            ("revoked", "=", True),
            "&",
            ("expires_at", "<", fields.Datetime.now()),
            "|",
            ("refresh_expires_at", "=", False),
            ("refresh_expires_at", "<", fields.Datetime.now()),
        ])
        expired.unlink()
        return True

    @api.model
    def create_token(
        self, client, user, scope=None, ip_address=None, user_agent=None
    ):
        """Create a new access token with optional refresh token"""
        now = datetime.now()
        access_expires = now + timedelta(seconds=client.access_token_expiry)
        refresh_expires = now + timedelta(seconds=client.refresh_token_expiry)

        return self.create({
            "token": secrets.token_urlsafe(32),
            "client_id": client.id,
            "user_id": user.id,
            "scope": scope,
            "expires_at": access_expires,
            "refresh_token": secrets.token_urlsafe(32),
            "refresh_expires_at": refresh_expires,
            "ip_address": ip_address,
            "user_agent": user_agent,
        })

    @api.model
    def find_by_token(self, token):
        """Find access token by token string"""
        domain = [("token", "=", token), ("revoked", "=", False)]
        return self.search(domain, limit=1)

    @api.model
    def find_by_refresh_token(self, refresh_token):
        """Find access token by refresh token string"""
        return self.search([
            ("refresh_token", "=", refresh_token),
            ("revoked", "=", False),
        ], limit=1)

    @api.model
    def validate_token_timing_safe(self, token_string):
        """
        Timing-safe token validation.
        Returns (token_record, is_valid) with consistent timing.
        """
        if not token_string:
            # Perform dummy operations to maintain timing
            secrets.compare_digest("dummy", "dummy")
            return None, False

        # Lookup token
        token = self.find_by_token(token_string)

        if not token:
            # Perform dummy validation to maintain timing
            secrets.compare_digest(token_string, "x" * len(token_string))
            return None, False

        # Verify token with constant-time comparison
        is_match = hmac.compare_digest(token.token, token_string)
        is_valid = is_match and token.is_valid()

        return token if is_valid else None, is_valid

    @api.model
    def validate_refresh_timing_safe(self, refresh_token_string):
        """
        Timing-safe refresh token validation.
        Returns (token_record, is_valid) with consistent timing.
        """
        if not refresh_token_string:
            secrets.compare_digest("dummy", "dummy")
            return None, False

        token = self.find_by_refresh_token(refresh_token_string)

        if not token:
            secrets.compare_digest(
                refresh_token_string, "x" * len(refresh_token_string)
            )
            return None, False

        # Verify with constant-time comparison
        is_match = hmac.compare_digest(
            token.refresh_token, refresh_token_string
        )
        is_valid = is_match and token.is_refresh_valid()

        return token if is_valid else None, is_valid
