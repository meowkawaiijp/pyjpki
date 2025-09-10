"""
This module provides various utility functions for working with JPKI certificates
and keys.
"""
from datetime import datetime

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature

def validate_certificate(cert: x509.Certificate, issuer_cert: x509.Certificate = None) -> bool:
    """
    Validates a certificate's expiration and signature.

    Args:
        cert: The certificate to validate.
        issuer_cert: The issuer's certificate. If provided, the signature is verified.
                     If None, only the expiration date is checked.

    Returns:
        True if the certificate is valid, False otherwise.
    """
    # Check expiration
    now = datetime.utcnow()
    if now < cert.not_valid_before or now > cert.not_valid_after:
        return False

    # Check signature if issuer certificate is provided
    if issuer_cert:
        try:
            issuer_cert.public_key().verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                cert.signature_hash_algorithm,
            )
        except InvalidSignature:
            return False

    return True

def cert_to_pem(cert: x509.Certificate) -> bytes:
    """
    Converts a certificate object to PEM format.

    Args:
        cert: The certificate to convert.

    Returns:
        The PEM-encoded certificate as bytes.
    """
    return cert.public_bytes(encoding=serialization.Encoding.PEM)

def public_key_to_pem(pubkey) -> bytes:
    """
    Converts a public key object to PEM format.

    Args:
        pubkey: The public key to convert (e.g., from cert.public_key()).

    Returns:
        The PEM-encoded public key as bytes.
    """
    return pubkey.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
