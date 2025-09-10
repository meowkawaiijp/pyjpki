"""
This module defines data structures for holding parsed certificate information.
"""
from dataclasses import dataclass
from datetime import datetime
from typing import Dict

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa

@dataclass
class JPKICertificate:
    """
    A dataclass to hold parsed information from a JPKI certificate.
    """
    subject: Dict[str, str]
    issuer: Dict[str, str]
    serial_number: int
    not_valid_before: datetime
    not_valid_after: datetime
    public_key: rsa.RSAPublicKey

    @classmethod
    def from_cryptography(cls, cert: x509.Certificate):
        """
        Creates a JPKICertificate instance from a cryptography Certificate object.
        """
        subject = {attr.rfc4514_attribute_name: attr.value for attr in cert.subject}
        issuer = {attr.rfc4514_attribute_name: attr.value for attr in cert.issuer}

        return cls(
            subject=subject,
            issuer=issuer,
            serial_number=cert.serial_number,
            not_valid_before=cert.not_valid_before,
            not_valid_after=cert.not_valid_after,
            public_key=cert.public_key(),
        )
