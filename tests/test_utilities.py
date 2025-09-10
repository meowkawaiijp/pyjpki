import pytest
from datetime import datetime, timedelta

from pyjpki.utilities import validate_certificate, cert_to_pem, public_key_to_pem
from cryptography import x509
from cryptography.hazmat.primitives import serialization

def test_cert_to_pem(test_cert_and_key):
    cert, _, _ = test_cert_and_key
    pem_bytes = cert_to_pem(cert)

    assert isinstance(pem_bytes, bytes)
    assert pem_bytes.startswith(b'-----BEGIN CERTIFICATE-----')

    # Check that it can be loaded back
    loaded_cert = x509.load_pem_x509_certificate(pem_bytes)
    assert loaded_cert.serial_number == cert.serial_number

def test_public_key_to_pem(test_cert_and_key):
    cert, _, _ = test_cert_and_key
    pubkey = cert.public_key()
    pem_bytes = public_key_to_pem(pubkey)

    assert isinstance(pem_bytes, bytes)
    assert pem_bytes.startswith(b'-----BEGIN PUBLIC KEY-----')

    # Check that it can be loaded back
    loaded_key = serialization.load_pem_public_key(pem_bytes)
    # Comparing the raw numbers is a reliable way to check for equality
    assert loaded_key.public_numbers() == pubkey.public_numbers()

def test_validate_certificate_valid(test_cert_and_key):
    cert, _, _ = test_cert_and_key
    assert validate_certificate(cert) is True

def test_validate_certificate_expired(test_cert_and_key):
    cert, _, _ = test_cert_and_key

    # Manually create an expired cert for testing this specific case
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes

    builder = x509.CertificateBuilder().subject_name(
        cert.subject
    ).issuer_name(
        cert.issuer
    ).public_key(
        cert.public_key()
    ).serial_number(
        cert.serial_number
    ).not_valid_before(
        datetime.utcnow() - timedelta(days=10)
    ).not_valid_after(
        datetime.utcnow() - timedelta(days=1) # Expired yesterday
    ).sign(test_cert_and_key[1], hashes.SHA256())

    assert validate_certificate(builder) is False

# Signature validation tests would require a more complex setup with a separate issuer cert.
# For now, this covers the expiration and basic checks.
