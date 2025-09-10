"""
Custom exceptions for the pyjpki library.
"""

class JPKIError(Exception):
    """Base exception class for all pyjpki errors."""
    pass

class APDUError(JPKIError):
    """
    Raised when an APDU command returns a non-9000 status word.
    """
    def __init__(self, message, sw1, sw2):
        self.sw1 = sw1
        self.sw2 = sw2
        super().__init__(f"{message} (SW1: {sw1:02X}, SW2: {sw2:02X})")

class PinVerificationError(APDUError):
    """
    Raised specifically when a PIN verification fails.
    """
    def __init__(self, sw1, sw2):
        self.retries_left = sw2 & 0x0F if sw1 == 0x63 else 0
        message = f"PIN verification failed. Retries left: {self.retries_left}"
        super().__init__(message, sw1, sw2)
