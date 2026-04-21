# Copyright 2025 Dubhe Srls
# License LGPL-3

import base64
import hashlib
import hmac
import secrets

from odoo import _, api, fields, models
from odoo.exceptions import ValidationError


class OAuth2Client(models.Model):
    _name = "oauth2.client"
    _description = "OAuth2 Client Application"
    _rec_name = "name"

    name = fields.Char(string="Application Name", required=True)
    active = fields.Boolean(default=True)

    client_id = fields.Char(
        string="Client ID",
        required=True,
        readonly=True,
        default=lambda self: secrets.token_urlsafe(24),
        copy=False,
    )
    client_secret = fields.Char(
        string="Client Secret",
        readonly=True,
        copy=False,
        help="Only shown once after creation. Store it securely.",
    )
    client_secret_hash = fields.Char(
        string="Client Secret Hash",
        readonly=True,
        copy=False,
    )

    client_type = fields.Selection([
        ("confidential", "Confidential (Server-side app)"),
        ("public", "Public (SPA, Mobile app)"),
    ], string="Client Type", default="confidential", required=True)

    redirect_uris = fields.Text(
        string="Redirect URIs",
        required=True,
        help="One URI per line. These are the allowed callback URLs.",
    )

    allowed_scopes = fields.Char(
        string="Allowed Scopes",
        default="openid profile email",
        help="Space-separated list of allowed scopes",
    )

    access_token_expiry = fields.Integer(
        string="Access Token Expiry (seconds)",
        default=3600,
        help="How long access tokens are valid (default: 1 hour)",
    )
    refresh_token_expiry = fields.Integer(
        string="Refresh Token Expiry (seconds)",
        default=86400 * 30,
        help="How long refresh tokens are valid (default: 30 days)",
    )

    # PKCE settings
    require_pkce = fields.Boolean(
        string="Require PKCE",
        default=True,
        help="Require Proof Key for Code Exchange (PKCE)",
    )

    # Client Credentials flow
    service_account_user_id = fields.Many2one(
        "res.users",
        string="Service Account User",
        domain=[("active", "=", True)],
        help="User for Client Credentials flow (machine-to-machine auth). "
             "When this client authenticates without user interaction, "
             "it will operate as this user.",
    )

    # Audit
    authorization_code_ids = fields.One2many(
        "oauth2.authorization_code", "client_id", string="Authorization Codes"
    )
    access_token_ids = fields.One2many(
        "oauth2.access_token", "client_id", string="Access Tokens"
    )

    description = fields.Text(string="Description")

    _sql_constraints = [
        ("client_id_unique", "UNIQUE(client_id)", "Client ID must be unique"),
    ]

    @api.model_create_multi
    def create(self, vals_list):
        for vals in vals_list:
            # Generate client secret for confidential clients
            if vals.get("client_type", "confidential") == "confidential":
                secret = secrets.token_urlsafe(32)
                vals["client_secret"] = secret
                vals["client_secret_hash"] = self._hash_secret(secret)
        return super().create(vals_list)

    def regenerate_secret(self):
        """Regenerate client secret and show it in a wizard"""
        self.ensure_one()
        if self.client_type != "confidential":
            msg = _("Public clients don't have a client secret")
            raise ValidationError(msg)

        secret = secrets.token_urlsafe(32)
        self.write({
            "client_secret": secret,
            "client_secret_hash": self._hash_secret(secret),
        })

        # Create wizard to show the new secret
        wizard = self.env["oauth2.show_secret.wizard"].create({
            "client_id": self.id,
            "client_secret": secret,
        })

        # Clear secret from client record immediately
        self.write({"client_secret": False})

        return {
            "type": "ir.actions.act_window",
            "name": _("New Client Secret"),
            "res_model": "oauth2.show_secret.wizard",
            "res_id": wizard.id,
            "view_mode": "form",
            "target": "new",
        }

    def clear_displayed_secret(self):
        """Clear the displayed secret after user has copied it"""
        self.ensure_one()
        self.write({"client_secret": False})

    def action_show_secret(self):
        """Show the client secret in a popup dialog"""
        self.ensure_one()
        if not self.client_secret:
            raise ValidationError(_(
                "No secret available. Click 'Regenerate Secret' to create one."
            ))

        return {
            "type": "ir.actions.client",
            "tag": "display_notification",
            "params": {
                "title": _("Client Secret"),
                "message": self.client_secret,
                "type": "info",
                "sticky": True,
            }
        }

    @staticmethod
    def _hash_secret(secret):
        """Hash a client secret for storage"""
        return hashlib.sha256(secret.encode()).hexdigest()

    def verify_secret(self, secret):
        """Verify a client secret using constant-time comparison"""
        self.ensure_one()
        if not secret or not self.client_secret_hash:
            return False
        computed_hash = self._hash_secret(secret)
        return hmac.compare_digest(self.client_secret_hash, computed_hash)

    def get_redirect_uris(self):
        """Return list of redirect URIs"""
        self.ensure_one()
        if not self.redirect_uris:
            return []
        uris = self.redirect_uris.split("\n")
        return [uri.strip() for uri in uris if uri.strip()]

    def validate_redirect_uri(self, uri):
        """Check if a redirect URI is allowed"""
        self.ensure_one()
        allowed = self.get_redirect_uris()
        return uri in allowed

    def validate_scope(self, scope):
        """Check if requested scopes are allowed"""
        self.ensure_one()
        if not scope:
            return True
        allowed = set(self.allowed_scopes.split())
        requested = set(scope.split())
        return requested.issubset(allowed)

    @staticmethod
    def verify_pkce(
        code_verifier, code_challenge, code_challenge_method="S256"
    ):
        """
        Verify PKCE code verifier against challenge (constant-time).
        Only S256 method is supported for security reasons.
        """
        if code_challenge_method != "S256":
            # Only S256 is allowed - plain method is insecure
            return False
        digest = hashlib.sha256(code_verifier.encode()).digest()
        computed = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
        return hmac.compare_digest(computed, code_challenge)

    def action_revoke_personal(self):
        """Revoke personal OAuth2 credentials (user can only revoke own)"""
        self.ensure_one()
        # Check user owns this credential
        if self.service_account_user_id != self.env.user:
            raise ValidationError(_(
                "You can only revoke your own credentials"
            ))
        self.sudo().write({"active": False})
        return {
            "type": "ir.actions.client",
            "tag": "display_notification",
            "params": {
                "title": _("Credentials Revoked"),
                "message": _(
                    "OAuth2 credentials '%s' have been revoked."
                ) % self.name,
                "type": "success",
            }
        }


class OAuth2ShowSecretWizard(models.TransientModel):
    """Wizard to display regenerated client secret"""
    _name = "oauth2.show_secret.wizard"
    _description = "Show Client Secret"

    client_id = fields.Many2one(
        "oauth2.client", string="Client", readonly=True
    )
    client_secret = fields.Char(string="Client Secret", readonly=True)
