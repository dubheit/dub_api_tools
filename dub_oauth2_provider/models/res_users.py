# Copyright 2025 Dubhe Srls
# License OPL-1
"""
Personal OAuth2 Clients for users.
Allows users to create their own OAuth2 client credentials.
"""

from odoo import _, api, fields, models
from odoo.exceptions import AccessDenied


class ResUsers(models.Model):
    _inherit = "res.users"

    oauth2_personal_client_ids = fields.One2many(
        "oauth2.client",
        "service_account_user_id",
        string="Personal OAuth2 Clients",
    )

    def action_create_personal_client(self):
        """Open wizard to create a personal OAuth2 client"""
        self.ensure_one()
        return {
            "type": "ir.actions.act_window",
            "name": _("Create OAuth2 Credentials"),
            "res_model": "oauth2.personal_client.wizard",
            "view_mode": "form",
            "target": "new",
            "context": {"default_user_id": self.id},
        }


class OAuth2PersonalClientWizard(models.TransientModel):
    """Wizard to create personal OAuth2 clients"""
    _name = "oauth2.personal_client.wizard"
    _description = "Create Personal OAuth2 Client"

    name = fields.Char(
        string="Description",
        required=True,
        help="A name to identify these credentials (e.g., 'Claude Desktop')",
    )
    user_id = fields.Many2one(
        "res.users",
        string="User",
        required=True,
        default=lambda self: (
            self.env.context.get('default_user_id') or self.env.user.id
        ),
    )

    # Result fields (shown after creation)
    client_created = fields.Boolean(
        string="Credentials Created", default=False
    )
    client_id = fields.Char(string="Client ID", readonly=True)
    client_secret = fields.Char(string="Client Secret", readonly=True)
    token_url = fields.Char(string="Token URL", readonly=True)
    authorization_url = fields.Char(string="Authorization URL", readonly=True)

    def action_create_client(self):
        """Create the personal OAuth2 client"""
        self.ensure_one()

        # Security check - users can only create for themselves
        if self.user_id != self.env.user and not self.env.user.has_group(
            "base.group_system"
        ):
            raise AccessDenied(_(
                "You can only create credentials for yourself"
            ))

        # Get base URL
        base_url = self.env["ir.config_parameter"].sudo().get_param(
            "web.base.url", "http://localhost:8069"
        )

        # Create OAuth2 client linked to this user
        client = self.env["oauth2.client"].sudo().create({
            "name": f"{self.name} ({self.user_id.name})",
            "client_type": "confidential",
            "redirect_uris": "http://localhost/callback",
            "service_account_user_id": self.user_id.id,
            "allowed_scopes": "openid profile email read write",
            "require_pkce": False,  # Not needed for client_credentials
        })

        # Save secret before clearing it from client record
        secret = client.client_secret

        # Show credentials to user
        self.write({
            "client_created": True,
            "client_id": client.client_id,
            "client_secret": secret,
            "token_url": f"{base_url}/oauth2/token",
            "authorization_url": f"{base_url}/oauth2/authorize",
        })

        # Clear secret from client record (only hash remains for verification)
        client.write({"client_secret": False})

        return {
            "type": "ir.actions.act_window",
            "res_model": self._name,
            "res_id": self.id,
            "view_mode": "form",
            "target": "new",
        }
