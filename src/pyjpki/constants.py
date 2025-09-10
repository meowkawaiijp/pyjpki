"""
This module contains constants used throughout the pyjpki library,
including APDU commands, file IDs (AID), and other static values.
"""
from pyasn1.type import univ

# APDU Commands
CLA_ISO7816 = 0x00
CLA_JPKI_SIGN = 0x80  # For COMPUTE DIGITAL SIGNATURE
INS_SELECT = 0xA4
INS_READ_BINARY = 0xB0
INS_VERIFY = 0x20
INS_COMPUTE_DIGITAL_SIGNATURE = 0x2A

# Application DFs (AID)
DF_JPKI = [0xD3, 0x92, 0xF0, 0x00, 0x26, 0x01, 0x00, 0x00, 0x00, 0x01]
DF_ATTRIBUTE = [0xD3, 0x92, 0x10, 0x00, 0x31, 0x00, 0x01, 0x01, 0x04, 0x08]

# JPKI EF File IDs
EF_AUTH_PIN = [0x00, 0x18]
EF_AUTH_KEY = [0x00, 0x17]
EF_AUTH_CERT = [0x00, 0x0A]

EF_SIGN_PIN = [0x00, 0x1B]
EF_SIGN_KEY = [0x00, 0x1A]
EF_SIGN_CERT = [0x00, 0x01]

# Attribute EF File IDs
EF_ATTR_PIN = [0x00, 0x11]
EF_MYNUMBER = [0x00, 0x01]
EF_4_BASIC_INFO = [0x00, 0x02]

# Status Words
SW_SUCCESS = (0x90, 0x00)
SW_VERIFY_FAIL_PREFIX = 0x63

# OIDs
OID_SHA256 = univ.ObjectIdentifier('2.16.840.1.101.3.4.2.1')
