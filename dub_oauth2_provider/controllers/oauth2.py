# Copyright 2025 Dubhe Srls
# License OPL-1

import json
import logging
from urllib.parse import urlencode, urlparse

from werkzeug.utils import redirect as werkzeug_redirect

from odoo import _, http
from odoo.http import Response, request

_logger = logging.getLogger(__name__)


class OAuth2Controller(http.Controller):
    """OAuth2 Authorization Server endpoints"""

    def _json_response(self, data, status=200, headers=None):
        """Return a JSON response with proper headers"""
        response_headers = [
            ("Content-Type", "application/json"),
            ("Cache-Control", "no-store"),
            ("Pragma", "no-cache"),
        ]
        if headers:
            response_headers.extend(headers)
        return Response(
            json.dumps(data),
            status=status,
            headers=response_headers,
        )

    def _error_response(self, error, description=None, uri=None, status=400):
        """Return an OAuth2 error response"""
        data = {"error": error}
        if description:
            data["error_description"] = description
        if uri:
            data["error_uri"] = uri
        return self._json_response(data, status=status)

    def _redirect_error(
        self, redirect_uri, error, description=None, state=None
    ):
        """Redirect with error parameters (external URL safe)"""
        params = {"error": error}
        if description:
            params["error_description"] = description
        if state:
            params["state"] = state
        sep = "&" if "?" in redirect_uri else "?"
        url = f"{redirect_uri}{sep}{urlencode(params)}"
        # Use werkzeug redirect directly to avoid Odoo adding language prefix
        return werkzeug_redirect(url, code=302)

    # ==================== AUTHORIZATION ENDPOINT ====================

    @http.route(
        "/oauth2/authorize", type="http", auth="user",
        methods=["GET", "POST"], csrf=False
    )
    def authorize(self, **kwargs):
        """
        OAuth2 Authorization Endpoint

        Handles the authorization request from the client application.
        User must be logged in to access this endpoint.
        """
        # Required parameters
        response_type = kwargs.get("response_type")
        client_id = kwargs.get("client_id")
        redirect_uri = kwargs.get("redirect_uri")

        # Optional parameters
        scope = kwargs.get("scope", "")
        state = kwargs.get("state")

        # PKCE parameters
        code_challenge = kwargs.get("code_challenge")
        code_challenge_method = kwargs.get("code_challenge_method", "S256")

        # Validate response_type
        if response_type != "code":
            if redirect_uri:
                return self._redirect_error(
                    redirect_uri,
                    "unsupported_response_type",
                    "Only 'code' response_type is supported",
                    state,
                )
            return self._error_response(
                "unsupported_response_type",
                "Only 'code' response_type is supported",
            )

        # Validate redirect_uri first (needed for auto-registration)
        if not redirect_uri:
            return self._error_response(
                "invalid_request", "redirect_uri is required"
            )

        # Validate client
        Client = request.env["oauth2.client"].sudo()
        domain = [("client_id", "=", client_id), ("active", "=", True)]
        client = Client.search(domain, limit=1)

        if not client:
            # Check if auto-registration is enabled (disabled by default)
            ICP = request.env["ir.config_parameter"].sudo()
            auto_reg = ICP.get_param(
                "oauth2.allow_auto_registration", "False"
            )
            if auto_reg.lower() not in ("true", "1", "yes"):
                return self._error_response(
                    "invalid_client",
                    "Unknown client_id. Contact administrator to register.",
                )

            # Auto-register the client (Dynamic Client Registration)
            parsed = urlparse(redirect_uri)
            # Only allow auto-reg for known trusted domains
            trusted_domains = ICP.get_param(
                "oauth2.trusted_domains", ""
            ).split(",")
            trusted_domains = [d.strip().lower() for d in trusted_domains]

            if parsed.netloc.lower() not in trusted_domains:
                return self._error_response(
                    "invalid_client",
                    f"Auto-registration not allowed for: {parsed.netloc}",
                )

            client_name = f"Auto: {parsed.netloc or 'Unknown'}"
            client = Client.create({
                "name": client_name,
                "client_id": client_id,
                "redirect_uris": redirect_uri,
                "client_type": "public",
                "require_pkce": bool(code_challenge),
                "allowed_scopes": "openid profile email",
            })

        # Validate redirect_uri against client's allowed URIs
        if not client.validate_redirect_uri(redirect_uri):
            return self._error_response(
                "invalid_request",
                "Invalid redirect_uri for this client.",
            )

        # Validate scope
        if scope and not client.validate_scope(scope):
            return self._redirect_error(
                redirect_uri,
                "invalid_scope",
                "Requested scope exceeds allowed scopes",
                state,
            )

        # Validate PKCE for public clients
        if client.require_pkce and not code_challenge:
            return self._redirect_error(
                redirect_uri,
                "invalid_request",
                "PKCE code_challenge is required",
                state,
            )

        if code_challenge and code_challenge_method != "S256":
            return self._redirect_error(
                redirect_uri,
                "invalid_request",
                "Invalid code_challenge_method. Only 'S256' is supported",
                state,
            )

        # Check if this is a consent POST or initial GET
        if request.httprequest.method == "POST":
            # Note: CSRF protection is provided by OAuth2 'state' parameter
            # which the client must validate. Traditional CSRF tokens don't
            # work reliably in OAuth2 flows due to cross-origin cookies.

            # User has consented, create authorization code
            consent = kwargs.get("consent")
            if consent != "allow":
                return self._redirect_error(
                    redirect_uri,
                    "access_denied",
                    "User denied the authorization request",
                    state,
                )

            # Create authorization code
            AuthCode = request.env["oauth2.authorization_code"].sudo()
            auth_code = AuthCode.create_code(
                client=client,
                user=request.env.user,
                redirect_uri=redirect_uri,
                scope=scope,
                code_challenge=code_challenge,
                code_challenge_method=code_challenge_method,
                state=state,
            )

            # Build redirect URL with authorization code
            params = {"code": auth_code.code}
            if state:
                params["state"] = state
            sep = "&" if "?" in redirect_uri else "?"
            redirect_url = f"{redirect_uri}{sep}{urlencode(params)}"

            # Show success page with auto-redirect
            return request.render("dub_oauth2_provider.oauth2_success_page", {
                "client_name": client.name,
                "redirect_url": redirect_url,
            })

        # GET request - show consent page
        return request.render("dub_oauth2_provider.consent_page", {
            "client": client,
            "scope": scope,
            "scope_list": scope.split() if scope else [],
            "redirect_uri": redirect_uri,
            "response_type": response_type,
            "state": state,
            "code_challenge": code_challenge,
            "code_challenge_method": code_challenge_method,
        })

    # ==================== TOKEN ENDPOINT ====================

    @http.route(
        "/oauth2/token", type="http", auth="none",
        methods=["POST"], csrf=False
    )
    def token(self, **kwargs):
        """
        OAuth2 Token Endpoint

        Exchanges authorization code for access token,
        or refreshes an existing token.
        """
        grant_type = kwargs.get("grant_type")

        if grant_type == "authorization_code":
            return self._handle_authorization_code_grant(**kwargs)
        elif grant_type == "refresh_token":
            return self._handle_refresh_token_grant(**kwargs)
        elif grant_type == "client_credentials":
            return self._handle_client_credentials_grant(**kwargs)
        else:
            return self._error_response(
                "unsupported_grant_type",
                "Supported grant_types: authorization_code, refresh_token, "
                "client_credentials",
            )

    def _handle_authorization_code_grant(self, **kwargs):
        """Handle authorization_code grant type"""
        code = kwargs.get("code")
        redirect_uri = kwargs.get("redirect_uri")
        client_id = kwargs.get("client_id")
        client_secret = kwargs.get("client_secret")
        code_verifier = kwargs.get("code_verifier")

        if not code:
            return self._error_response("invalid_request", "code is required")

        if not redirect_uri:
            return self._error_response(
                "invalid_request", "redirect_uri is required"
            )

        # Find and validate authorization code
        AuthCode = request.env["oauth2.authorization_code"].sudo()
        auth_code = AuthCode.search([("code", "=", code)], limit=1)

        if not auth_code or not auth_code.is_valid():
            return self._error_response(
                "invalid_grant", "Invalid or expired authorization code"
            )

        client = auth_code.client_id

        # Validate client_id
        if client_id and client_id != client.client_id:
            return self._error_response("invalid_client", "client_id mismatch")

        # Validate client_secret for confidential clients
        if client.client_type == "confidential":
            if not client_secret or not client.verify_secret(client_secret):
                return self._error_response(
                    "invalid_client",
                    "Invalid client credentials",
                    status=401,
                )

        # Validate redirect_uri matches
        if redirect_uri != auth_code.redirect_uri:
            return self._error_response(
                "invalid_grant", "redirect_uri mismatch"
            )

        # Validate PKCE
        if auth_code.code_challenge:
            if not code_verifier:
                return self._error_response(
                    "invalid_request", "code_verifier is required"
                )
            if not client.verify_pkce(
                code_verifier,
                auth_code.code_challenge,
                auth_code.code_challenge_method,
            ):
                return self._error_response(
                    "invalid_grant", "Invalid code_verifier"
                )

        # Mark code as used atomically to prevent race conditions
        if not auth_code.mark_used_atomic():
            return self._error_response(
                "invalid_grant",
                "Authorization code has already been used"
            )

        # Create access token
        AccessToken = request.env["oauth2.access_token"].sudo()
        token = AccessToken.create_token(
            client=client,
            user=auth_code.user_id,
            scope=auth_code.scope,
            ip_address=request.httprequest.remote_addr,
            user_agent=(
                request.httprequest.user_agent.string
                if request.httprequest.user_agent else None
            ),
        )

        # Return token response
        expires_in = int(
            (token.expires_at - token.created_at).total_seconds()
        )
        response_data = {
            "access_token": token.token,
            "token_type": token.token_type,
            "expires_in": expires_in,
        }

        if token.refresh_token:
            response_data["refresh_token"] = token.refresh_token

        if token.scope:
            response_data["scope"] = token.scope

        return self._json_response(response_data)

    def _handle_refresh_token_grant(self, **kwargs):
        """Handle refresh_token grant type"""
        refresh_token = kwargs.get("refresh_token")
        client_id = kwargs.get("client_id")
        client_secret = kwargs.get("client_secret")
        scope = kwargs.get("scope")

        if not refresh_token:
            return self._error_response(
                "invalid_request", "refresh_token is required"
            )

        # Find token by refresh token
        AccessToken = request.env["oauth2.access_token"].sudo()
        old_token = AccessToken.find_by_refresh_token(refresh_token)

        if not old_token or not old_token.is_refresh_valid():
            return self._error_response(
                "invalid_grant", "Invalid or expired refresh token"
            )

        client = old_token.client_id

        # Validate client
        if client_id and client_id != client.client_id:
            return self._error_response("invalid_client", "client_id mismatch")

        if client.client_type == "confidential":
            if not client_secret or not client.verify_secret(client_secret):
                return self._error_response(
                    "invalid_client",
                    "Invalid client credentials",
                    status=401,
                )

        # Validate scope (must be subset of original)
        if scope:
            if old_token.scope:
                original_scopes = set(old_token.scope.split())
            else:
                original_scopes = set()
            requested_scopes = set(scope.split())
            if not requested_scopes.issubset(original_scopes):
                return self._error_response(
                    "invalid_scope",
                    "Requested scope exceeds original grant"
                )
        else:
            scope = old_token.scope

        # Revoke old token
        old_token.revoke()

        # Create new token
        new_token = AccessToken.create_token(
            client=client,
            user=old_token.user_id,
            scope=scope,
            ip_address=request.httprequest.remote_addr,
            user_agent=(
                request.httprequest.user_agent.string
                if request.httprequest.user_agent else None
            ),
        )

        # Return token response
        expires_in = int(
            (new_token.expires_at - new_token.created_at).total_seconds()
        )
        response_data = {
            "access_token": new_token.token,
            "token_type": new_token.token_type,
            "expires_in": expires_in,
        }

        if new_token.refresh_token:
            response_data["refresh_token"] = new_token.refresh_token

        if new_token.scope:
            response_data["scope"] = new_token.scope

        return self._json_response(response_data)

    def _handle_client_credentials_grant(self, **kwargs):
        """Handle client_credentials grant type (machine-to-machine)"""
        client_id = kwargs.get("client_id")
        client_secret = kwargs.get("client_secret")
        scope = kwargs.get("scope")

        if not client_id:
            return self._error_response(
                "invalid_request", "client_id is required"
            )

        if not client_secret:
            return self._error_response(
                "invalid_request", "client_secret is required"
            )

        # Find and validate client
        Client = request.env["oauth2.client"].sudo()
        client = Client.search([
            ("client_id", "=", client_id),
            ("active", "=", True)
        ], limit=1)

        if not client:
            return self._error_response(
                "invalid_client", "Unknown client_id", status=401
            )

        # Verify client secret
        if not client.verify_secret(client_secret):
            return self._error_response(
                "invalid_client", "Invalid client credentials", status=401
            )

        # Check if service account user is configured
        if not client.service_account_user_id:
            return self._error_response(
                "invalid_client",
                "No service account user configured for this client. "
                "Use authorization_code grant instead.",
            )

        # Validate scope
        if scope and not client.validate_scope(scope):
            return self._error_response(
                "invalid_scope", "Requested scope exceeds allowed scopes"
            )

        # Create access token for service account user
        AccessToken = request.env["oauth2.access_token"].sudo()
        token = AccessToken.create_token(
            client=client,
            user=client.service_account_user_id,
            scope=scope or client.allowed_scopes,
            ip_address=request.httprequest.remote_addr,
            user_agent=(
                request.httprequest.user_agent.string
                if request.httprequest.user_agent else None
            ),
        )

        # Return token response
        expires_in = int(
            (token.expires_at - token.created_at).total_seconds()
        )
        response_data = {
            "access_token": token.token,
            "token_type": token.token_type,
            "expires_in": expires_in,
        }

        if token.scope:
            response_data["scope"] = token.scope

        # Note: No refresh_token for client_credentials grant (per RFC 6749)
        return self._json_response(response_data)

    # ==================== USERINFO ENDPOINT ====================

    @http.route(
        "/oauth2/userinfo", type="http", auth="none",
        methods=["GET", "POST"], csrf=False
    )
    def userinfo(self, **kwargs):
        """
        OAuth2 UserInfo Endpoint

        Returns information about the authenticated user.
        Requires Bearer token authentication.
        """
        # Get token from Authorization header
        auth_header = request.httprequest.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return self._error_response(
                "invalid_token",
                "Bearer token required",
                status=401,
            )

        token_string = auth_header[7:]  # Remove "Bearer " prefix

        # Find and validate token
        AccessToken = request.env["oauth2.access_token"].sudo()
        token = AccessToken.find_by_token(token_string)

        if not token or not token.is_valid():
            return self._error_response(
                "invalid_token",
                "Invalid or expired token",
                status=401,
            )

        # Update last used
        token.update_last_used(request.httprequest.remote_addr)

        # Build userinfo response based on scope
        user = token.user_id
        scopes = set(token.scope.split()) if token.scope else set()

        userinfo = {"sub": str(user.id)}

        if "profile" in scopes or "openid" in scopes:
            userinfo["name"] = user.name
            if user.login:
                userinfo["preferred_username"] = user.login

        if "email" in scopes:
            if user.email:
                userinfo["email"] = user.email
                userinfo["email_verified"] = True  # Assume verified in Odoo

        return self._json_response(userinfo)

    # ==================== REVOKE ENDPOINT ====================

    @http.route(
        "/oauth2/revoke", type="http", auth="none",
        methods=["POST"], csrf=False
    )
    def revoke(self, **kwargs):
        """
        OAuth2 Token Revocation Endpoint

        Revokes an access token or refresh token.
        """
        token_string = kwargs.get("token")
        token_type_hint = kwargs.get("token_type_hint")
        client_id = kwargs.get("client_id")
        client_secret = kwargs.get("client_secret")

        if not token_string:
            return self._error_response("invalid_request", "token is required")

        AccessToken = request.env["oauth2.access_token"].sudo()

        # Try to find token
        if token_type_hint == "refresh_token":
            token = AccessToken.find_by_refresh_token(token_string)
        else:
            token = AccessToken.find_by_token(token_string)
            if not token:
                token = AccessToken.find_by_refresh_token(token_string)

        if token:
            # Validate client if provided
            if client_id:
                if token.client_id.client_id != client_id:
                    return self._error_response(
                        "invalid_client",
                        "Token does not belong to this client"
                    )

                if token.client_id.client_type == "confidential":
                    is_valid = (
                        client_secret
                        and token.client_id.verify_secret(client_secret)
                    )
                    if not is_valid:
                        return self._error_response(
                            "invalid_client",
                            "Invalid client credentials",
                            status=401,
                        )

            token.revoke()

        # Always return 200, even if token not found (per RFC 7009)
        return self._json_response({})

    # ==================== WELL-KNOWN ENDPOINT ====================

    @http.route(
        "/.well-known/oauth-authorization-server",
        type="http", auth="none", methods=["GET"], csrf=False
    )
    def oauth_metadata(self, **kwargs):
        """
        OAuth2 Authorization Server Metadata (RFC 8414)

        Returns server configuration for clients.
        """
        base_url = request.env["ir.config_parameter"].sudo().get_param(
            "web.base.url", "http://localhost:8069"
        )

        metadata = {
            "issuer": base_url,
            "authorization_endpoint": f"{base_url}/oauth2/authorize",
            "token_endpoint": f"{base_url}/oauth2/token",
            "userinfo_endpoint": f"{base_url}/oauth2/userinfo",
            "revocation_endpoint": f"{base_url}/oauth2/revoke",
            "registration_endpoint": f"{base_url}/oauth2/register",
            "response_types_supported": ["code"],
            "response_modes_supported": ["query"],
            "grant_types_supported": [
                "authorization_code", "refresh_token", "client_credentials"
            ],
            "token_endpoint_auth_methods_supported": [
                "client_secret_post",
                "none",
            ],
            "scopes_supported": ["openid", "profile", "email"],
            "code_challenge_methods_supported": ["S256"],
        }

        return self._json_response(metadata)

    @http.route(
        "/.well-known/openid-configuration",
        type="http", auth="none", methods=["GET"], csrf=False
    )
    def openid_configuration(self, **kwargs):
        """
        OpenID Connect Discovery Document

        Alias for oauth-authorization-server metadata.
        """
        return self.oauth_metadata(**kwargs)

    @http.route(
        "/.well-known/oauth-protected-resource",
        type="http", auth="none", methods=["GET"], csrf=False
    )
    def oauth_protected_resource(self, **kwargs):
        """
        OAuth2 Protected Resource Metadata (RFC 8707)

        Indicates which authorization server protects this resource.
        Used by MCP clients to discover OAuth2 configuration.
        """
        base_url = request.env["ir.config_parameter"].sudo().get_param(
            "web.base.url", "http://localhost:8069"
        )

        metadata = {
            "resource": base_url,
            "authorization_servers": [base_url],
            "bearer_methods_supported": ["header"],
            "scopes_supported": ["openid", "profile", "email"],
        }

        return self._json_response(metadata)

    # Resource-specific discovery endpoints (RFC 8414)
    # These handle requests like /.well-known/oauth-authorization-server/mcp/sse

    @http.route(
        "/.well-known/oauth-authorization-server/<path:resource_path>",
        type="http", auth="none", methods=["GET"], csrf=False
    )
    def oauth_metadata_resource(self, resource_path=None, **kwargs):
        """Resource-specific OAuth2 metadata - returns same as root"""
        return self.oauth_metadata(**kwargs)

    @http.route(
        "/.well-known/openid-configuration/<path:resource_path>",
        type="http", auth="none", methods=["GET"], csrf=False
    )
    def openid_configuration_resource(self, resource_path=None, **kwargs):
        """Resource-specific OpenID configuration - returns same as root"""
        return self.oauth_metadata(**kwargs)

    @http.route(
        "/.well-known/oauth-protected-resource/<path:resource_path>",
        type="http", auth="none", methods=["GET"], csrf=False
    )
    def oauth_protected_resource_path(self, resource_path=None, **kwargs):
        """Resource-specific protected resource metadata - returns same as root"""
        return self.oauth_protected_resource(**kwargs)

    # ==================== DYNAMIC CLIENT REGISTRATION ====================

    @http.route(
        "/oauth2/register", type="http", auth="none",
        methods=["POST"], csrf=False
    )
    def register_client(self, **kwargs):
        """
        OAuth2 Dynamic Client Registration (RFC 7591)

        Allows clients to register themselves dynamically.
        """
        ICP = request.env["ir.config_parameter"].sudo()
        if not ICP.get_param("oauth2.allow_dynamic_registration", "False") == "True":
            return self._error_response(
                "invalid_request",
                "Dynamic client registration is disabled.",
                status=403,
            )

        try:
            # Parse JSON body
            body = request.httprequest.get_data(as_text=True)
            if body:
                data = json.loads(body)
            else:
                data = kwargs
        except json.JSONDecodeError:
            return self._error_response(
                "invalid_request", "Invalid JSON body", status=400
            )

        # Extract client metadata
        client_name = data.get("client_name", "Dynamic Client")
        redirect_uris = data.get("redirect_uris", [])
        token_endpoint_auth_method = data.get(
            "token_endpoint_auth_method", "none"
        )
        grant_types = data.get("grant_types", ["authorization_code"])
        response_types = data.get("response_types", ["code"])

        # Validate redirect_uris
        if not redirect_uris:
            return self._error_response(
                "invalid_redirect_uri",
                "At least one redirect_uri is required",
                status=400
            )

        # Normalize redirect_uris to string (one per line)
        if isinstance(redirect_uris, list):
            redirect_uris_str = "\n".join(redirect_uris)
        else:
            redirect_uris_str = redirect_uris

        # Determine client type based on auth method
        if token_endpoint_auth_method == "none":
            client_type = "public"
        else:
            client_type = "confidential"

        # Create the client
        Client = request.env["oauth2.client"].sudo()
        client = Client.create({
            "name": client_name,
            "redirect_uris": redirect_uris_str,
            "client_type": client_type,
            "require_pkce": True,  # Always require PKCE for dynamic clients
            "allowed_scopes": "openid profile email",
        })

        # Build response
        base_url = request.env["ir.config_parameter"].sudo().get_param(
            "web.base.url", "http://localhost:8069"
        )

        response_data = {
            "client_id": client.client_id,
            "client_name": client.name,
            "redirect_uris": client.get_redirect_uris(),
            "token_endpoint_auth_method": (
                "none" if client.client_type == "public"
                else "client_secret_post"
            ),
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            "registration_client_uri": (
                f"{base_url}/oauth2/register/{client.client_id}"
            ),
        }

        # Include client_secret for confidential clients
        if client.client_type == "confidential" and client.client_secret:
            response_data["client_secret"] = client.client_secret
            # Clear secret after returning (security)
            client.sudo().write({"client_secret": False})

        return self._json_response(response_data, status=201)
