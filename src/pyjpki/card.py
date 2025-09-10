"""
This module provides classes for managing connections to smart card readers
and cards using the pyscard library.
"""
from typing import List, Optional, Tuple

import hashlib
import logging
from typing import List, Optional, Tuple

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from pyasn1.type import univ, namedtype, tag
from pyasn1.codec.der import encoder as der_encoder
from smartcard.System import readers
from smartcard.pcsc.PCSCExceptions import BaseSCardException
from smartcard.CardConnection import CardConnection
from smartcard.reader.Reader import Reader

from .constants import (
    CLA_ISO7816,
    CLA_JPKI_SIGN,
    INS_SELECT,
    INS_VERIFY,
    INS_READ_BINARY,
    INS_COMPUTE_DIGITAL_SIGNATURE,
    DF_JPKI,
    DF_ATTRIBUTE,
    EF_AUTH_PIN,
    EF_SIGN_PIN,
    EF_ATTR_PIN,
    EF_AUTH_CERT,
    EF_SIGN_CERT,
    EF_AUTH_KEY,
    EF_SIGN_KEY,
    EF_4_BASIC_INFO,
    SW_SUCCESS,
    SW_VERIFY_FAIL_PREFIX,
    OID_SHA256,
)
from .exceptions import APDUError, PinVerificationError


logger = logging.getLogger(__name__)


class CardManager:
    """
    A class to manage the connection to a smart card.

    This class is a context manager that handles the connection and disconnection
    of a smart card.
    """

    def __init__(self, reader_index: int = 0):
        """
        Initializes the CardManager.

        Args:
            reader_index: The index of the reader to use from the list of available readers.
        """
        self.reader_index = reader_index
        self._reader: Optional[Reader] = None
        self._connection: Optional[CardConnection] = None
        self._cert_cache: dict = {}
        logger.info("CardManager initialized for reader index %d", reader_index)

    @staticmethod
    def get_readers() -> List[str]:
        """
        Gets a list of available smart card reader names.

        Returns:
            A list of strings, where each string is the name of a connected reader.
        """
        try:
            return [str(r) for r in readers()]
        except BaseSCardException:
            return []

    def connect(self) -> None:
        """
        Establishes a connection to the smart card in the selected reader.

        Raises:
            RuntimeError: If no readers are found or if the specified reader index is invalid.
            Exception: Propagates exceptions from pyscard during connection.
        """
        reader_list = readers()
        if not reader_list:
            raise RuntimeError("No smart card readers found.")

        if self.reader_index >= len(reader_list):
            raise RuntimeError(f"Reader index {self.reader_index} is out of bounds.")

        self._reader = reader_list[self.reader_index]
        logger.debug("Connecting to reader: %s", self._reader)
        self._connection = self._reader.createConnection()
        self._connection.connect()
        logger.info("Connected to card.")

    def disconnect(self) -> None:
        """
        Disconnects from the smart card.
        """
        if self._connection:
            self._connection.disconnect()
            self._connection = None
            self._reader = None
            logger.info("Disconnected from card.")

    @property
    def is_connected(self) -> bool:
        """
        Checks if a connection to a card is active.

        Returns:
            True if connected, False otherwise.
        """
        return self._connection is not None

    @property
    def connection(self) -> Optional[CardConnection]:
        """
        Returns the raw pyscard CardConnection object.

        Returns:
            The CardConnection object if connected, otherwise None.
        """
        return self._connection

    def __enter__(self):
        """
        Context manager entry point. Connects to the card.
        """
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """
        Context manager exit point. Disconnects from the card.
        """
        self.disconnect()

    def _transmit(self, apdu: List[int]) -> Tuple[List[int], int, int]:
        """
        Transmits an APDU command and handles basic error checking.

        Args:
            apdu: The APDU command to transmit.

        Returns:
            A tuple of (data, sw1, sw2).

        Raises:
            APDUError: If the transmission fails or the card returns a non-success status word.
            RuntimeError: If not connected to a card.
        """
        if not self.connection:
            raise RuntimeError("Not connected to a card.")

        logger.debug("--> %s", " ".join(f"{b:02X}" for b in apdu))
        data, sw1, sw2 = self.connection.transmit(apdu)
        logger.debug("<-- %s (SW: %02X %02X)", " ".join(f"{b:02X}" for b in data), sw1, sw2)

        if (sw1, sw2) != SW_SUCCESS:
            # Pin verification failures are handled separately
            if sw1 != SW_VERIFY_FAIL_PREFIX:
                raise APDUError(f"APDU command failed: {apdu}", sw1, sw2)
        return data, sw1, sw2

    def verify_pin(self, pin: str, pin_type: str = "auth") -> int:
        """
        Verifies a PIN against the card.

        Args:
            pin: The PIN to verify.
            pin_type: The type of PIN to verify. One of 'auth', 'sign', or 'attr'.

        Returns:
            The number of retries left after a successful verification.

        Raises:
            PinVerificationError: If the PIN is incorrect.
            APDUError: For other card communication errors.
            ValueError: If an invalid pin_type is provided.
        """
        if pin_type == "auth":
            df = DF_JPKI
            ef = EF_AUTH_PIN
        elif pin_type == "sign":
            df = DF_JPKI
            ef = EF_SIGN_PIN
        elif pin_type == "attr":
            df = DF_ATTRIBUTE
            ef = EF_ATTR_PIN
        else:
            raise ValueError(f"Invalid pin_type: {pin_type}")

        # 1. Select DF
        apdu = [CLA_ISO7816, INS_SELECT, 0x04, 0x0C, len(df)] + df
        self._transmit(apdu)

        # 2. Select EF (PIN file)
        apdu = [CLA_ISO7816, INS_SELECT, 0x02, 0x0C, len(ef)] + ef
        self._transmit(apdu)

        # 3. Verify PIN
        pin_bytes = [ord(c) for c in pin]
        apdu = [CLA_ISO7816, INS_VERIFY, 0x00, 0x80, len(pin_bytes)] + pin_bytes

        if not self.connection:
            raise RuntimeError("Not connected to a card.")
        data, sw1, sw2 = self.connection.transmit(apdu)

        if (sw1, sw2) == SW_SUCCESS:
            return 3 # Nominal success value, as counter is reset.
        elif sw1 == SW_VERIFY_FAIL_PREFIX:
            raise PinVerificationError(sw1, sw2)
        else:
            raise APDUError("Unexpected error during PIN verification", sw1, sw2)

    def read_certificate(self, cert_type: str = "auth") -> x509.Certificate:
        """
        Reads a certificate from the card.
        """
        if cert_type in self._cert_cache:
            return self._cert_cache[cert_type]

        if cert_type == "auth":
            ef = EF_AUTH_CERT
        elif cert_type == "sign":
            ef = EF_SIGN_CERT
        else:
            raise ValueError(f"Invalid cert_type: {cert_type}")

        apdu = [CLA_ISO7816, INS_SELECT, 0x04, 0x0C, len(DF_JPKI)] + DF_JPKI
        self._transmit(apdu)

        apdu = [CLA_ISO7816, INS_SELECT, 0x02, 0x0C, len(ef)] + ef
        self._transmit(apdu)

        apdu = [CLA_ISO7816, INS_READ_BINARY, 0x00, 0x00, 0x00]
        cert_data, _, _ = self._transmit(apdu)

        cert = x509.load_der_x509_certificate(bytes(cert_data), default_backend())
        self._cert_cache[cert_type] = cert
        return cert

    def get_certificate_info(self, cert_type: str = "auth"):
        """
        Reads a certificate from the card and returns a simplified data structure.
        """
        from .certificate import JPKICertificate

        cert_obj = self.read_certificate(cert_type)
        return JPKICertificate.from_cryptography(cert_obj)

    def sign_data(self, data_to_sign: bytes, sign_type: str = "auth") -> bytes:
        """
        Signs a hash of the given data using a private key on the card.
        """
        if sign_type == "auth":
            ef = EF_AUTH_KEY
        elif sign_type == "sign":
            ef = EF_SIGN_KEY
        else:
            raise ValueError(f"Invalid sign_type: {sign_type}")

        apdu = [CLA_ISO7816, INS_SELECT, 0x04, 0x0C, len(DF_JPKI)] + DF_JPKI
        self._transmit(apdu)

        apdu = [CLA_ISO7816, INS_SELECT, 0x02, 0x0C, len(ef)] + ef
        self._transmit(apdu)

        sha256_hash = hashlib.sha256(data_to_sign).digest()

        class AlgorithmIdentifier(univ.Sequence):
            componentType = namedtype.NamedTypes(
                namedtype.NamedType('algorithm', univ.ObjectIdentifier()),
                namedtype.OptionalNamedType('parameters', univ.Null())
            )

        class DigestInfo(univ.Sequence):
            componentType = namedtype.NamedTypes(
                namedtype.NamedType('digestAlgorithm', AlgorithmIdentifier()),
                namedtype.NamedType('digest', univ.OctetString())
            )

        alg_id = AlgorithmIdentifier()
        alg_id.setComponentByName('algorithm', OID_SHA256)
        alg_id.setComponentByName('parameters', univ.Null())

        digest_info = DigestInfo()
        digest_info.setComponentByName('digestAlgorithm', alg_id)
        digest_info.setComponentByName('digest', univ.OctetString(sha256_hash))

        der_encoded_digest_info = der_encoder.encode(digest_info)

        apdu = (
            [CLA_JPKI_SIGN, INS_COMPUTE_DIGITAL_SIGNATURE, 0x00, 0x80, len(der_encoded_digest_info)]
            + list(der_encoded_digest_info)
            + [0x00]
        )

        data, _, _ = self._transmit(apdu)
        return bytes(data)

    def read_personal_info(self):
        """
        Reads the 4 basic personal attributes from the card.
        """
        from .personal_info import JPKIPersonalInfo

        apdu = [CLA_ISO7816, INS_SELECT, 0x04, 0x0C, len(DF_ATTRIBUTE)] + DF_ATTRIBUTE
        self._transmit(apdu)

        apdu = [CLA_ISO7816, INS_SELECT, 0x02, 0x0C, len(EF_4_BASIC_INFO)] + EF_4_BASIC_INFO
        self._transmit(apdu)

        apdu = [CLA_ISO7816, INS_READ_BINARY, 0x00, 0x00, 0x00]
        data, _, _ = self._transmit(apdu)

        return JPKIPersonalInfo.from_tlv_data(bytes(data))
