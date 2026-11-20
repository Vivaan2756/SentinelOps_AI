"""Comprehensive Unit Tests for Stage 2: Manifest Crypto & Normalization Core.

Tests cover:
1. Canonical origin normalization:
   - IPv4 dotted-decimal formatting and default ports.
   - IPv6 RFC 5952 compression and bracketed representation.
   - IDNA / Punycode conversion for internationalized domain names.
   - Rejection of credentials, path traversal, double slashes, query strings, fragments.
2. Parameter digest calculation using RFC 8785 canonicalization.
3. ExecutionManifest schema validation:
   - Strict extra='forbid' rejection.
   - UUID and hex format validations.
   - Lifetime limits (max 120s).
   - HTTP rejection in staging and production.
   - HTTP restriction to localhost in development.
4. Cryptographic Ed25519 signing and verification:
   - Roundtrip sign and verify success.
   - Tampered manifest payload rejection.
   - Tampered signature rejection.
   - Expired manifest rejection.
   - Clock skew tolerance.
   - Wrong key_id rejection.
   - Wrong environment rejection.
   - Wrong audience / issuer rejection.
"""

import base64
import time
import uuid
import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519

from app.core.manifest_crypto import (
    ExecutionManifest,
    ManifestSecurityError,
    NormalizedOrigin,
    compute_parameters_digest,
    normalize_origin_and_path,
    sign_manifest,
    verify_manifest,
)


@pytest.fixture
def keypair():
    """Generate an ephemeral Ed25519 keypair for testing."""
    priv = ed25519.Ed25519PrivateKey.generate()
    pub = priv.public_key()
    return priv, pub


@pytest.fixture
def valid_manifest_data():
    """Create a valid baseline dictionary for ExecutionManifest."""
    now = int(time.time())
    return {
        "manifest_version": "1.0",
        "key_id": "test-key-1",
        "issuer": "sentinelops.control-plane",
        "audience": "sentinelops.execution",
        "environment": "development",
        "manifest_id": str(uuid.uuid4()),
        "execution_id": str(uuid.uuid4()),
        "approval_id": str(uuid.uuid4()),
        "approval_reference": f"{uuid.uuid4()}:v1",
        "workspace_id": str(uuid.uuid4()),
        "service_id": str(uuid.uuid4()),
        "action_id": "execute_http_recovery",
        "authorized_scheme": "https",
        "authorized_hostname": "api.payments.example.com",
        "authorized_port": 443,
        "authorized_path": "/admin/recovery/reset",
        "parameters_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "issued_at": now,
        "expires_at": now + 60,
    }


class TestOriginNormalization:
    """Test deterministic origin and path normalization."""

    def test_standard_https_url_default_port(self):
        """Standard HTTPS URL normalizes to port 443."""
        norm = normalize_origin_and_path("https://api.example.com/health")
        assert norm.scheme == "https"
        assert norm.hostname == "api.example.com"
        assert norm.port == 443
        assert norm.path == "/health"
        assert norm.canonical_origin == "https://api.example.com:443"
        assert norm.canonical_url == "https://api.example.com:443/health"

    def test_standard_http_url_default_port(self):
        """Standard HTTP URL normalizes to port 80."""
        norm = normalize_origin_and_path("http://localhost/api/status")
        assert norm.scheme == "http"
        assert norm.hostname == "localhost"
        assert norm.port == 80
        assert norm.path == "/api/status"
        assert norm.canonical_origin == "http://localhost:80"

    def test_explicit_nonstandard_port(self):
        """Explicit non-standard port is preserved."""
        norm = normalize_origin_and_path("https://api.example.com:8443/recovery")
        assert norm.scheme == "https"
        assert norm.hostname == "api.example.com"
        assert norm.port == 8443
        assert norm.path == "/recovery"
        assert norm.canonical_origin == "https://api.example.com:8443"

    def test_trailing_dot_removed(self):
        """Trailing FQDN dot is stripped from hostname."""
        norm = normalize_origin_and_path("https://api.example.com./health")
        assert norm.hostname == "api.example.com"

    def test_ipv4_literal(self):
        """IPv4 address is normalized to dotted-decimal."""
        norm = normalize_origin_and_path("http://127.0.0.1:9100/health")
        assert norm.hostname == "127.0.0.1"
        assert norm.port == 9100

    def test_ipv6_literal_compressed(self):
        """IPv6 address is normalized to RFC 5952 compressed representation in brackets."""
        norm = normalize_origin_and_path("https://[2001:0db8:0000:0000:0000:0000:0000:0001]:443/status")
        assert norm.hostname == "[2001:db8::1]"
        assert norm.canonical_origin == "https://[2001:db8::1]:443"

    def test_idna_punycode_conversion(self):
        """Internationalized domain name (IDN) is converted to ASCII Punycode with strict UTS #46."""
        norm = normalize_origin_and_path("https://münchen-api.de/ops/recover")
        assert norm.hostname == "xn--mnchen-api-9db.de"
        assert norm.canonical_origin == "https://xn--mnchen-api-9db.de:443"

    def test_idna_std3_and_transitional_rejections(self):
        """Strict STD3 rules reject invalid label characters and malformed hyphens."""
        # Leading hyphen in domain label
        with pytest.raises(ManifestSecurityError, match="Malformed or invalid domain name"):
            normalize_origin_and_path("https://-badlabel.com/health")

        # Trailing hyphen in domain label
        with pytest.raises(ManifestSecurityError, match="Malformed or invalid domain name"):
            normalize_origin_and_path("https://badlabel-.com/health")

        # Invalid character (space) in hostname
        with pytest.raises(ManifestSecurityError, match="Malformed or invalid domain name"):
            normalize_origin_and_path("https://bad host.com/health")

    def test_rejections(self):
        """Malformed, ambiguous, or dangerous URLs are strictly rejected."""
        # Userinfo credentials rejected
        with pytest.raises(ManifestSecurityError, match="Embedded credentials"):
            normalize_origin_and_path("https://user:pass@api.example.com/health")

        # Invalid scheme
        with pytest.raises(ManifestSecurityError, match="Invalid URL scheme"):
            normalize_origin_and_path("ftp://api.example.com/health")

        # Path traversal
        with pytest.raises(ManifestSecurityError, match="Path traversal"):
            normalize_origin_and_path("https://api.example.com/admin/../secret")

        # Double slashes
        with pytest.raises(ManifestSecurityError, match="Double slashes"):
            normalize_origin_and_path("https://api.example.com//admin/secret")

        # Query strings
        with pytest.raises(ManifestSecurityError, match="Query strings are prohibited"):
            normalize_origin_and_path("https://api.example.com/health?query=1")

        # URL fragments
        with pytest.raises(ManifestSecurityError, match="URL fragments are prohibited"):
            normalize_origin_and_path("https://api.example.com/health#fragment")

        # Percent encoding
        with pytest.raises(ManifestSecurityError, match="Percent-encoded sequences are prohibited"):
            normalize_origin_and_path("https://api.example.com/admin/%2e%2e/reset")


class TestParameterDigest:
    """Test deterministic RFC 8785 parameter hashing."""

    def test_parameter_digest_deterministic(self):
        """Identical dictionaries with different key insertion orders produce identical digests."""
        dict1 = {"timeout_seconds": 30, "recovery_path": "/reset", "codes": [200, 204]}
        dict2 = {"codes": [200, 204], "recovery_path": "/reset", "timeout_seconds": 30}
        digest1 = compute_parameters_digest(dict1)
        digest2 = compute_parameters_digest(dict2)
        assert digest1 == digest2
        assert len(digest1) == 64

    def test_empty_or_none_parameters(self):
        """Empty dictionary or None yields hash of '{}'."""
        digest_none = compute_parameters_digest(None)
        digest_empty = compute_parameters_digest({})
        assert digest_none == digest_empty


class TestExecutionManifestValidation:
    """Test Pydantic model validation on ExecutionManifest."""

    def test_valid_manifest_construction(self, valid_manifest_data):
        """Valid data constructs an ExecutionManifest cleanly."""
        manifest = ExecutionManifest.model_validate(valid_manifest_data)
        assert manifest.manifest_version == "1.0"
        assert manifest.authorized_port == 443

    def test_extra_fields_forbidden(self, valid_manifest_data):
        """Extra fields are rejected (extra='forbid')."""
        valid_manifest_data["injected_field"] = "malicious"
        with pytest.raises(Exception, match="extra_forbidden"):
            ExecutionManifest.model_validate(valid_manifest_data)

    def test_http_scheme_rejected_in_production(self, valid_manifest_data):
        """HTTP scheme is strictly rejected in production."""
        valid_manifest_data["environment"] = "production"
        valid_manifest_data["authorized_scheme"] = "http"
        valid_manifest_data["authorized_hostname"] = "127.0.0.1"
        with pytest.raises(Exception, match="Plain HTTP is strictly forbidden"):
            ExecutionManifest.model_validate(valid_manifest_data)

    def test_http_scheme_allowed_only_for_localhost_in_dev(self, valid_manifest_data):
        """In development, HTTP is permitted ONLY for localhost origins."""
        valid_manifest_data["environment"] = "development"
        valid_manifest_data["authorized_scheme"] = "http"

        # Localhost accepted
        valid_manifest_data["authorized_hostname"] = "127.0.0.1"
        m1 = ExecutionManifest.model_validate(valid_manifest_data)
        assert m1.authorized_scheme == "http"

        # Non-localhost rejected
        valid_manifest_data["authorized_hostname"] = "api.external.com"
        with pytest.raises(Exception, match="HTTP scheme is restricted to localhost"):
            ExecutionManifest.model_validate(valid_manifest_data)

    def test_lifetime_boundary_validation(self, valid_manifest_data):
        """
        Verify exact lifetime boundary:
        - 60 seconds is accepted.
        - 61 seconds is rejected.
        - 120 seconds is rejected.
        """
        # Exactly 60 seconds -> Accepted
        valid_manifest_data["expires_at"] = valid_manifest_data["issued_at"] + 60
        manifest = ExecutionManifest.model_validate(valid_manifest_data)
        assert manifest.expires_at - manifest.issued_at == 60

        # 61 seconds -> Rejected
        valid_manifest_data["expires_at"] = valid_manifest_data["issued_at"] + 61
        with pytest.raises(Exception, match="exceeds maximum allowed lifetime"):
            ExecutionManifest.model_validate(valid_manifest_data)

        # 120 seconds -> Rejected
        valid_manifest_data["expires_at"] = valid_manifest_data["issued_at"] + 120
        with pytest.raises(Exception, match="exceeds maximum allowed lifetime"):
            ExecutionManifest.model_validate(valid_manifest_data)


class TestManifestSigningAndVerification:
    """Test cryptographic Ed25519 signing and verification."""

    def test_sign_and_verify_roundtrip_success(self, keypair, valid_manifest_data):
        """A properly signed manifest verifies cleanly."""
        priv, pub = keypair
        manifest = ExecutionManifest.model_validate(valid_manifest_data)
        sig = sign_manifest(manifest, priv)

        public_keys = {"test-key-1": pub}
        verified = verify_manifest(
            manifest_data=valid_manifest_data,
            signature_b64=sig,
            public_keys=public_keys,
            expected_environment="development",
            now_utc_ts=manifest.issued_at + 10,
        )
        assert verified.manifest_id == manifest.manifest_id

    def test_tampered_payload_rejected(self, keypair, valid_manifest_data):
        """Tampering with any manifest field causes signature verification to fail."""
        priv, pub = keypair
        manifest = ExecutionManifest.model_validate(valid_manifest_data)
        sig = sign_manifest(manifest, priv)

        tampered_data = valid_manifest_data.copy()
        # Tamper authorized_hostname
        tampered_data["authorized_hostname"] = "evil.example.com"

        public_keys = {"test-key-1": pub}
        with pytest.raises(ManifestSecurityError, match="signature does not match manifest"):
            verify_manifest(
                manifest_data=tampered_data,
                signature_b64=sig,
                public_keys=public_keys,
                expected_environment="development",
                now_utc_ts=manifest.issued_at + 10,
            )

    def test_tampered_signature_rejected(self, keypair, valid_manifest_data):
        """Corrupted signature bytes (preserving length or corrupting bytes) are rejected."""
        priv, pub = keypair
        manifest = ExecutionManifest.model_validate(valid_manifest_data)
        sig = sign_manifest(manifest, priv)

        # Decode, flip bits in signature bytes, re-encode to preserve 64-byte length
        sig_bytes = bytearray(base64.urlsafe_b64decode(sig.encode("ascii")))
        sig_bytes[0] ^= 0xFF
        corrupt_sig = base64.urlsafe_b64encode(sig_bytes).decode("ascii")

        public_keys = {"test-key-1": pub}
        with pytest.raises(ManifestSecurityError, match="signature does not match manifest"):
            verify_manifest(
                manifest_data=valid_manifest_data,
                signature_b64=corrupt_sig,
                public_keys=public_keys,
                expected_environment="development",
                now_utc_ts=manifest.issued_at + 10,
            )

    def test_malformed_signature_length_rejected(self, keypair, valid_manifest_data):
        """Signature with invalid byte length is rejected."""
        priv, pub = keypair
        manifest = ExecutionManifest.model_validate(valid_manifest_data)
        public_keys = {"test-key-1": pub}
        with pytest.raises(ManifestSecurityError, match="Malformed base64 signature"):
            verify_manifest(
                manifest_data=valid_manifest_data,
                signature_b64="bm90LWEtdmFsaWQtNjQtYnl0ZS1zaWduYXR1cmU=",
                public_keys=public_keys,
                expected_environment="development",
                now_utc_ts=manifest.issued_at + 10,
            )

    def test_expired_manifest_rejected(self, keypair, valid_manifest_data):
        """Manifest evaluated after expires_at is rejected."""
        priv, pub = keypair
        manifest = ExecutionManifest.model_validate(valid_manifest_data)
        sig = sign_manifest(manifest, priv)

        public_keys = {"test-key-1": pub}
        # Current time 1 second past expires_at
        with pytest.raises(ManifestSecurityError, match="Manifest has expired"):
            verify_manifest(
                manifest_data=valid_manifest_data,
                signature_b64=sig,
                public_keys=public_keys,
                expected_environment="development",
                now_utc_ts=manifest.expires_at + 1,
            )

    def test_future_issued_at_beyond_skew_rejected(self, keypair, valid_manifest_data):
        """Manifest issued in the future beyond clock skew tolerance (5s) is rejected."""
        priv, pub = keypair
        now = int(time.time())
        valid_manifest_data["issued_at"] = now + 10
        valid_manifest_data["expires_at"] = now + 70
        manifest = ExecutionManifest.model_validate(valid_manifest_data)
        sig = sign_manifest(manifest, priv)

        public_keys = {"test-key-1": pub}
        with pytest.raises(ManifestSecurityError, match="is in the future"):
            verify_manifest(
                manifest_data=valid_manifest_data,
                signature_b64=sig,
                public_keys=public_keys,
                expected_environment="development",
                now_utc_ts=now,
            )

    def test_unknown_key_id_rejected(self, keypair, valid_manifest_data):
        """Manifest referencing an unconfigured key_id is rejected."""
        priv, pub = keypair
        valid_manifest_data["key_id"] = "unknown-key-99"
        manifest = ExecutionManifest.model_validate(valid_manifest_data)
        sig = sign_manifest(manifest, priv)

        public_keys = {"test-key-1": pub}
        with pytest.raises(ManifestSecurityError, match="Unknown key_id"):
            verify_manifest(
                manifest_data=valid_manifest_data,
                signature_b64=sig,
                public_keys=public_keys,
                expected_environment="development",
                now_utc_ts=manifest.issued_at + 10,
            )

    def test_wrong_environment_rejected(self, keypair, valid_manifest_data):
        """Manifest issued for 'staging' submitted to 'production' broker is rejected."""
        priv, pub = keypair
        valid_manifest_data["environment"] = "staging"
        manifest = ExecutionManifest.model_validate(valid_manifest_data)
        sig = sign_manifest(manifest, priv)

        public_keys = {"test-key-1": pub}
        with pytest.raises(ManifestSecurityError, match="Environment mismatch"):
            verify_manifest(
                manifest_data=valid_manifest_data,
                signature_b64=sig,
                public_keys=public_keys,
                expected_environment="production",
                now_utc_ts=manifest.issued_at + 10,
            )

    def test_broker_audience_manifest_verification(self, keypair, valid_manifest_data):
        """Manifest issued with 'sentinelops.broker' verifies cleanly when expected_audience='sentinelops.broker'."""
        priv, pub = keypair
        valid_manifest_data["audience"] = "sentinelops.broker"
        manifest = ExecutionManifest.model_validate(valid_manifest_data)
        sig = sign_manifest(manifest, priv)

        public_keys = {"test-key-1": pub}
        verified = verify_manifest(
            manifest_data=valid_manifest_data,
            signature_b64=sig,
            public_keys=public_keys,
            expected_environment="development",
            now_utc_ts=manifest.issued_at + 10,
            expected_audience="sentinelops.broker",
        )
        assert verified.audience == "sentinelops.broker"

    def test_mismatched_audience_rejected(self, keypair, valid_manifest_data):
        """Manifest with broker audience rejected when expecting execution audience."""
        priv, pub = keypair
        valid_manifest_data["audience"] = "sentinelops.broker"
        manifest = ExecutionManifest.model_validate(valid_manifest_data)
        sig = sign_manifest(manifest, priv)

        public_keys = {"test-key-1": pub}
        with pytest.raises(ManifestSecurityError, match="Invalid manifest audience 'sentinelops.broker'. Expected 'sentinelops.execution'"):
            verify_manifest(
                manifest_data=valid_manifest_data,
                signature_b64=sig,
                public_keys=public_keys,
                expected_environment="development",
                now_utc_ts=manifest.issued_at + 10,
                expected_audience="sentinelops.execution",
            )
