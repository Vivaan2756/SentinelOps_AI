"""Test suite for URL and target SSRF validator."""

import pytest
from app.detector.validator import validate_target_url, SSRFValidationError


def test_valid_urls():
    """Verify standard legitimate HTTP and HTTPS URLs are accepted."""
    assert validate_target_url("http://example.com/health")[0] is True
    assert validate_target_url("https://api.sentinelops.io/v1/health")[0] is True
    assert validate_target_url("http://127.0.0.1:8001/health", allow_local=True)[0] is True
    assert validate_target_url("http://localhost:8001/health", allow_local=True)[0] is True


def test_invalid_schemes():
    """Verify dangerous non-HTTP schemes are blocked."""
    with pytest.raises(SSRFValidationError, match="Only http and https"):
        validate_target_url("ftp://example.com/resource")

    with pytest.raises(SSRFValidationError, match="Only http and https"):
        validate_target_url("file:///etc/passwd")

    with pytest.raises(SSRFValidationError, match="Only http and https"):
        validate_target_url("gopher://127.0.0.1:70")


def test_embedded_credentials():
    """Verify embedded credentials in URLs are blocked."""
    with pytest.raises(SSRFValidationError, match="credentials"):
        validate_target_url("http://admin:secret@127.0.0.1:8000/health")


def test_cloud_metadata_blocking():
    """Verify cloud metadata IPs and hosts are strictly blocked."""
    with pytest.raises(SSRFValidationError, match="metadata destination"):
        validate_target_url("http://169.254.169.254/latest/meta-data/")

    with pytest.raises(SSRFValidationError, match="metadata destination"):
        validate_target_url("http://metadata.google.internal/computeMetadata/v1/")

    with pytest.raises(SSRFValidationError, match="metadata destination"):
        validate_target_url("http://169.254.170.2/v2/credentials")


def test_loopback_restriction_when_disabled():
    """Verify loopback is rejected when allow_local=False."""
    with pytest.raises(SSRFValidationError, match="loopback"):
        validate_target_url("http://127.0.0.1:8000/health", allow_local=False)

    with pytest.raises(SSRFValidationError, match="localhost"):
        validate_target_url("http://localhost:8000/health", allow_local=False)
