# Copyright 2025 Dubhe Srls
# License LGPL-3

import base64
import hashlib
import json
import secrets

from odoo.tests.common import HttpCase, TransactionCase, tagged


@tagged("post_install", "-at_install")
class TestOAuth2Models(TransactionCase):
    """Test OAuth2 models and logic"""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.Client = cls.env["oauth2.client"]
        cls.AuthCode = cls.env["oauth2.authorization_code"]
        cls.AccessToken = cls.env["oauth2.access_token"]

    def test_client_creation_confidential(self):
        """Test confidential client creation with secret"""
        client = self.Client.create({
            "name": "Test Confidential Client",
            "redirect_uris": "https://example.com/callback",
            "client_type": "confidential",
        })
        self.assertTrue(client.client_id)
        self.assertTrue(client.client_secret_hash)
        self.assertEqual(client.client_type, "confidential")

    def test_client_creation_public(self):
        """Test public client creation without secret"""
        client = self.Client.create({
            "name": "Test Public Client",
            "redirect_uris": "https://example.com/callback",
            "client_type": "public",
        })
        self.assertTrue(client.client_id)
        self.assertFalse(client.client_secret_hash)
        self.assertEqual(client.client_type, "public")

    def test_client_validate_redirect_uri(self):
        """Test redirect URI validation"""
        client = self.Client.create({
            "name": "Test Client",
            "redirect_uris": "https://example.com/callback\nhttps://app.example.com/auth",
            "client_type": "public",
        })
        self.assertTrue(client.validate_redirect_uri("https://example.com/callback"))
        self.assertTrue(client.validate_redirect_uri("https://app.example.com/auth"))
        self.assertFalse(client.validate_redirect_uri("https://evil.com/callback"))

    def test_client_validate_scope(self):
        """Test scope validation"""
        client = self.Client.create({
            "name": "Test Client",
            "redirect_uris": "https://example.com/callback",
            "client_type": "public",
            "allowed_scopes": "openid profile email",
        })
        self.assertTrue(client.validate_scope("openid"))
        self.assertTrue(client.validate_scope("openid profile"))
        self.assertTrue(client.validate_scope("openid profile email"))
        self.assertFalse(client.validate_scope("admin"))
        self.assertFalse(client.validate_scope("openid admin"))

    def test_pkce_verification(self):
        """Test PKCE code verifier validation"""
        # Generate PKCE pair
        code_verifier = secrets.token_urlsafe(32)
        digest = hashlib.sha256(code_verifier.encode()).digest()
        code_challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()

        # Valid verification
        self.assertTrue(
            self.Client.verify_pkce(code_verifier, code_challenge, "S256")
        )

        # Invalid verifier
        self.assertFalse(
            self.Client.verify_pkce("wrong_verifier", code_challenge, "S256")
        )

        # Plain method not supported
        self.assertFalse(
            self.Client.verify_pkce(code_verifier, code_verifier, "plain")
        )

    def test_authorization_code_creation(self):
        """Test authorization code creation and validation"""
        client = self.Client.create({
            "name": "Test Client",
            "redirect_uris": "https://example.com/callback",
            "client_type": "public",
        })

        auth_code = self.AuthCode.create_code(
            client=client,
            user=self.env.user,
            redirect_uri="https://example.com/callback",
            scope="openid profile",
        )

        self.assertTrue(auth_code.code)
        self.assertTrue(auth_code.is_valid())

        # Mark as used
        auth_code.mark_used()
        self.assertFalse(auth_code.is_valid())

    def test_access_token_creation(self):
        """Test access token creation and validation"""
        client = self.Client.create({
            "name": "Test Client",
            "redirect_uris": "https://example.com/callback",
            "client_type": "public",
        })

        token = self.AccessToken.create_token(
            client=client,
            user=self.env.user,
            scope="openid profile",
        )

        self.assertTrue(token.token)
        self.assertTrue(token.refresh_token)
        self.assertTrue(token.is_valid())
        self.assertTrue(token.is_refresh_valid())

        # Revoke
        token.revoke()
        self.assertFalse(token.is_valid())
        self.assertFalse(token.is_refresh_valid())

    def test_token_lookup(self):
        """Test token lookup methods"""
        client = self.Client.create({
            "name": "Test Client",
            "redirect_uris": "https://example.com/callback",
            "client_type": "public",
        })

        token = self.AccessToken.create_token(
            client=client,
            user=self.env.user,
            scope="openid",
        )

        # Find by access token
        found = self.AccessToken.find_by_token(token.token)
        self.assertEqual(found.id, token.id)

        # Find by refresh token
        found = self.AccessToken.find_by_refresh_token(token.refresh_token)
        self.assertEqual(found.id, token.id)

        # Not found for invalid token
        found = self.AccessToken.find_by_token("invalid_token")
        self.assertFalse(found)


@tagged("post_install", "-at_install")
class TestOAuth2Http(HttpCase):
    """Test OAuth2 HTTP endpoints"""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        # Create test client
        cls.test_client = cls.env["oauth2.client"].create({
            "name": "Test HTTP Client",
            "redirect_uris": "https://example.com/callback",
            "client_type": "public",
            "require_pkce": False,
        })

    def test_well_known_endpoint(self):
        """Test OAuth2 metadata endpoint"""
        response = self.url_open("/.well-known/oauth-authorization-server")
        self.assertEqual(response.status_code, 200)

        data = json.loads(response.content)
        self.assertIn("authorization_endpoint", data)
        self.assertIn("token_endpoint", data)
        self.assertIn("userinfo_endpoint", data)
        self.assertIn("revocation_endpoint", data)
        self.assertEqual(data["response_types_supported"], ["code"])
        self.assertIn("authorization_code", data["grant_types_supported"])

    def test_openid_configuration_endpoint(self):
        """Test OpenID Connect discovery endpoint"""
        response = self.url_open("/.well-known/openid-configuration")
        self.assertEqual(response.status_code, 200)

        data = json.loads(response.content)
        self.assertIn("authorization_endpoint", data)

    def test_token_endpoint_invalid_grant(self):
        """Test token endpoint with invalid grant type"""
        response = self.url_open(
            "/oauth2/token",
            data={"grant_type": "invalid"},
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        # RFC 6749 section 5.2: error responses return 400
        self.assertEqual(response.status_code, 400)

        data = json.loads(response.content)
        self.assertEqual(data["error"], "unsupported_grant_type")

    def test_token_endpoint_missing_code(self):
        """Test token endpoint with missing authorization code"""
        response = self.url_open(
            "/oauth2/token",
            data={
                "grant_type": "authorization_code",
                "redirect_uri": "https://example.com/callback",
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        data = json.loads(response.content)
        self.assertEqual(data["error"], "invalid_request")
        self.assertIn("code", data["error_description"])

    def test_token_exchange_flow(self):
        """Test complete token exchange flow"""
        # Create authorization code programmatically
        auth_code = self.env["oauth2.authorization_code"].create_code(
            client=self.test_client,
            user=self.env.user,
            redirect_uri="https://example.com/callback",
            scope="openid profile",
        )

        # Exchange code for token
        response = self.url_open(
            "/oauth2/token",
            data={
                "grant_type": "authorization_code",
                "code": auth_code.code,
                "redirect_uri": "https://example.com/callback",
                "client_id": self.test_client.client_id,
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        self.assertEqual(response.status_code, 200)

        data = json.loads(response.content)
        self.assertIn("access_token", data)
        self.assertIn("refresh_token", data)
        self.assertEqual(data["token_type"], "Bearer")
        self.assertIn("expires_in", data)

        return data["access_token"], data["refresh_token"]

    def test_token_exchange_with_pkce(self):
        """Test token exchange with PKCE"""
        # Create PKCE client
        pkce_client = self.env["oauth2.client"].create({
            "name": "Test PKCE Client",
            "redirect_uris": "https://example.com/callback",
            "client_type": "public",
            "require_pkce": True,
        })

        # Generate PKCE pair
        code_verifier = secrets.token_urlsafe(32)
        digest = hashlib.sha256(code_verifier.encode()).digest()
        code_challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()

        # Create authorization code with PKCE
        auth_code = self.env["oauth2.authorization_code"].create_code(
            client=pkce_client,
            user=self.env.user,
            redirect_uri="https://example.com/callback",
            scope="openid",
            code_challenge=code_challenge,
            code_challenge_method="S256",
        )

        # Exchange code for token with verifier
        response = self.url_open(
            "/oauth2/token",
            data={
                "grant_type": "authorization_code",
                "code": auth_code.code,
                "redirect_uri": "https://example.com/callback",
                "client_id": pkce_client.client_id,
                "code_verifier": code_verifier,
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        self.assertEqual(response.status_code, 200)

        data = json.loads(response.content)
        self.assertIn("access_token", data)

    def test_token_exchange_pkce_invalid_verifier(self):
        """Test token exchange with invalid PKCE verifier"""
        pkce_client = self.env["oauth2.client"].create({
            "name": "Test PKCE Client 2",
            "redirect_uris": "https://example.com/callback",
            "client_type": "public",
            "require_pkce": True,
        })

        code_verifier = secrets.token_urlsafe(32)
        digest = hashlib.sha256(code_verifier.encode()).digest()
        code_challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()

        auth_code = self.env["oauth2.authorization_code"].create_code(
            client=pkce_client,
            user=self.env.user,
            redirect_uri="https://example.com/callback",
            scope="openid",
            code_challenge=code_challenge,
            code_challenge_method="S256",
        )

        # Try with wrong verifier
        response = self.url_open(
            "/oauth2/token",
            data={
                "grant_type": "authorization_code",
                "code": auth_code.code,
                "redirect_uri": "https://example.com/callback",
                "client_id": pkce_client.client_id,
                "code_verifier": "wrong_verifier",
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )

        data = json.loads(response.content)
        self.assertEqual(data["error"], "invalid_grant")

    def test_userinfo_endpoint(self):
        """Test userinfo endpoint with valid token"""
        # Get a valid token
        auth_code = self.env["oauth2.authorization_code"].create_code(
            client=self.test_client,
            user=self.env.user,
            redirect_uri="https://example.com/callback",
            scope="openid profile email",
        )

        response = self.url_open(
            "/oauth2/token",
            data={
                "grant_type": "authorization_code",
                "code": auth_code.code,
                "redirect_uri": "https://example.com/callback",
                "client_id": self.test_client.client_id,
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        token_data = json.loads(response.content)
        access_token = token_data["access_token"]

        # Call userinfo endpoint
        response = self.url_open(
            "/oauth2/userinfo",
            headers={"Authorization": f"Bearer {access_token}"},
        )
        self.assertEqual(response.status_code, 200)

        data = json.loads(response.content)
        self.assertIn("sub", data)
        self.assertIn("name", data)

    def test_userinfo_endpoint_invalid_token(self):
        """Test userinfo endpoint with invalid token"""
        response = self.url_open(
            "/oauth2/userinfo",
            headers={"Authorization": "Bearer invalid_token"},
        )
        self.assertEqual(response.status_code, 401)

    def test_userinfo_endpoint_no_token(self):
        """Test userinfo endpoint without token"""
        response = self.url_open("/oauth2/userinfo")
        self.assertEqual(response.status_code, 401)

    def test_refresh_token_flow(self):
        """Test refresh token flow"""
        # Get initial token
        auth_code = self.env["oauth2.authorization_code"].create_code(
            client=self.test_client,
            user=self.env.user,
            redirect_uri="https://example.com/callback",
            scope="openid profile",
        )

        response = self.url_open(
            "/oauth2/token",
            data={
                "grant_type": "authorization_code",
                "code": auth_code.code,
                "redirect_uri": "https://example.com/callback",
                "client_id": self.test_client.client_id,
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        token_data = json.loads(response.content)
        refresh_token = token_data["refresh_token"]

        # Refresh the token
        response = self.url_open(
            "/oauth2/token",
            data={
                "grant_type": "refresh_token",
                "refresh_token": refresh_token,
                "client_id": self.test_client.client_id,
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        self.assertEqual(response.status_code, 200)

        new_token_data = json.loads(response.content)
        self.assertIn("access_token", new_token_data)
        self.assertIn("refresh_token", new_token_data)
        # New tokens should be different
        self.assertNotEqual(new_token_data["refresh_token"], refresh_token)

    def test_revoke_token(self):
        """Test token revocation"""
        # Get a token
        auth_code = self.env["oauth2.authorization_code"].create_code(
            client=self.test_client,
            user=self.env.user,
            redirect_uri="https://example.com/callback",
            scope="openid",
        )

        response = self.url_open(
            "/oauth2/token",
            data={
                "grant_type": "authorization_code",
                "code": auth_code.code,
                "redirect_uri": "https://example.com/callback",
                "client_id": self.test_client.client_id,
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        token_data = json.loads(response.content)
        access_token = token_data["access_token"]

        # Revoke the token
        response = self.url_open(
            "/oauth2/revoke",
            data={
                "token": access_token,
                "client_id": self.test_client.client_id,
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        self.assertEqual(response.status_code, 200)

        # Try to use the revoked token
        response = self.url_open(
            "/oauth2/userinfo",
            headers={"Authorization": f"Bearer {access_token}"},
        )
        self.assertEqual(response.status_code, 401)

    def test_revoke_nonexistent_token(self):
        """Test revoking a non-existent token returns 200 (per RFC 7009)"""
        response = self.url_open(
            "/oauth2/revoke",
            data={"token": "nonexistent_token"},
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        # RFC 7009 specifies 200 OK even for non-existent tokens
        self.assertEqual(response.status_code, 200)

    def test_code_reuse_prevention(self):
        """Test that authorization codes cannot be reused"""
        auth_code = self.env["oauth2.authorization_code"].create_code(
            client=self.test_client,
            user=self.env.user,
            redirect_uri="https://example.com/callback",
            scope="openid",
        )

        # First exchange should succeed
        response = self.url_open(
            "/oauth2/token",
            data={
                "grant_type": "authorization_code",
                "code": auth_code.code,
                "redirect_uri": "https://example.com/callback",
                "client_id": self.test_client.client_id,
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        self.assertEqual(response.status_code, 200)

        # Second exchange should fail
        response = self.url_open(
            "/oauth2/token",
            data={
                "grant_type": "authorization_code",
                "code": auth_code.code,
                "redirect_uri": "https://example.com/callback",
                "client_id": self.test_client.client_id,
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        data = json.loads(response.content)
        self.assertEqual(data["error"], "invalid_grant")
