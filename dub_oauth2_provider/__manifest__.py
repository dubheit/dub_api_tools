{
    "name": "OAuth2 Provider",
    "summary": "Use Odoo as an OAuth2 Authorization Server",
    "description": """
        Transform Odoo into an OAuth2 Authorization Server for secure
        authentication of external applications and AI tools.

        Features:
        - Authorization Code flow with PKCE support
        - Client Credentials flow (machine-to-machine)
        - Personal OAuth2 credentials (users can create from Preferences)
        - Refresh token rotation
        - Userinfo endpoint (OpenID Connect compatible)
        - Configurable token expiration
        - Auto-registration with trusted domains whitelist
        - Consent page for user authorization
        - Full client management interface
    """,
    "version": "19.0.1.0.2",
    "category": "Tools",
    "author": "Dubhe Srls",
    "website": "https://dubhe.it",
    "license": "LGPL-3",
    "depends": ["base", "web"],
    "data": [
        "security/security.xml",
        "security/ir.model.access.csv",
        "views/oauth2_token_views.xml",
        "views/oauth2_client_views.xml",
        "views/oauth2_personal_token_views.xml",
        "views/oauth2_menus.xml",
        "data/oauth2_defaults.xml",
    ],
    "images": ["static/description/banner.png"],
    "installable": True,
    "application": False,
}
