import pytest
from unittest.mock import patch, MagicMock, call
import datetime
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

from pyjpki.card import CardManager
from pyjpki.exceptions import APDUError, PinVerificationError
from pyjpki.constants import OID_SHA256
import hashlib

@pytest.fixture
def card_manager():
    """Fixture to provide a CardManager instance."""
    return CardManager()

@patch('pyjpki.card.readers')
def test_get_readers_success(mock_readers):
    """Tests that get_readers returns a list of reader names."""
    mock_reader_obj = MagicMock()
    mock_reader_obj.__str__.return_value = "Fake Reader 1"
    mock_readers.return_value = [mock_reader_obj]

    readers = CardManager.get_readers()
    assert readers == ["Fake Reader 1"]
    mock_readers.assert_called_once()

@patch('pyjpki.card.readers')
def test_get_readers_no_readers(mock_readers):
    """Tests that get_readers returns an empty list when no readers are found."""
    mock_readers.return_value = []
    readers = CardManager.get_readers()
    assert readers == []

@patch('pyjpki.card.readers')
def test_connect_disconnect(mock_readers, card_manager):
    """Tests the basic connect and disconnect flow."""
    mock_reader = MagicMock()
    mock_connection = MagicMock()
    mock_reader.createConnection.return_value = mock_connection
    mock_readers.return_value = [mock_reader]

    card_manager.connect()
    assert card_manager.is_connected is True
    mock_connection.connect.assert_called_once()

    card_manager.disconnect()
    assert card_manager.is_connected is False
    mock_connection.disconnect.assert_called_once()

@patch('pyjpki.card.readers')
def test_transmit_success(mock_readers, card_manager):
    """Tests the _transmit helper on success."""
    mock_reader = MagicMock()
    mock_connection = MagicMock()
    mock_reader.createConnection.return_value = mock_connection
    mock_readers.return_value = [mock_reader]

    card_manager.connect()

    apdu = [0x00, 0x01, 0x02, 0x03]
    response_data = [0xAA, 0xBB]
    mock_connection.transmit.return_value = (response_data, 0x90, 0x00)

    data, sw1, sw2 = card_manager._transmit(apdu)

    assert data == response_data
    assert (sw1, sw2) == (0x90, 0x00)
    mock_connection.transmit.assert_called_with(apdu)

@patch('pyjpki.card.readers')
def test_transmit_failure(mock_readers, card_manager):
    """Tests that _transmit raises APDUError on failure."""
    mock_reader = MagicMock()
    mock_connection = MagicMock()
    mock_reader.createConnection.return_value = mock_connection
    mock_readers.return_value = [mock_reader]
    card_manager.connect()

    apdu = [0x00, 0x01, 0x02, 0x03]
    mock_connection.transmit.return_value = ([], 0x6A, 0x82) # File not found

    with pytest.raises(APDUError) as excinfo:
        card_manager._transmit(apdu)

    assert excinfo.value.sw1 == 0x6A
    assert excinfo.value.sw2 == 0x82

@patch('pyjpki.card.readers')
def test_verify_pin_success(mock_readers, card_manager):
    """Tests successful PIN verification."""
    mock_reader = MagicMock()
    mock_connection = MagicMock()
    mock_reader.createConnection.return_value = mock_connection
    mock_readers.return_value = [mock_reader]
    card_manager.connect()

    mock_connection.transmit.return_value = ([], 0x90, 0x00)

    pin = "1234"
    retries = card_manager.verify_pin(pin, pin_type="auth")

    assert retries == 3 # Nominal success value

    apdu_calls = mock_connection.transmit.call_args_list
    assert len(apdu_calls) == 3
    assert apdu_calls[0] == call([0x00, 0xA4, 0x04, 0x0C, 10, 0xD3, 0x92, 0xF0, 0x00, 0x26, 0x01, 0x00, 0x00, 0x00, 0x01])
    assert apdu_calls[1] == call([0x00, 0xA4, 0x02, 0x0C, 2, 0x00, 0x18])
    assert apdu_calls[2] == call([0x00, 0x20, 0x00, 0x80, 4, 0x31, 0x32, 0x33, 0x34])

@patch('pyjpki.card.readers')
def test_verify_pin_failure(mock_readers, card_manager):
    """Tests failed PIN verification and retry counter."""
    mock_reader = MagicMock()
    mock_connection = MagicMock()
    mock_reader.createConnection.return_value = mock_connection
    mock_readers.return_value = [mock_reader]
    card_manager.connect()

    mock_connection.transmit.side_effect = [
        ([], 0x90, 0x00),
        ([], 0x90, 0x00),
        ([], 0x63, 0xC2),
    ]

    with pytest.raises(PinVerificationError) as excinfo:
        card_manager.verify_pin("1111", pin_type="auth")

    assert excinfo.value.retries_left == 2
    assert "Retries left: 2" in str(excinfo.value)

@patch('pyjpki.card.readers')
def test_read_certificate(mock_readers, card_manager, test_cert_and_key):
    """Tests reading and parsing a certificate from the card."""
    _, _, der_cert = test_cert_and_key

    mock_reader = MagicMock()
    mock_connection = MagicMock()
    mock_reader.createConnection.return_value = mock_connection
    mock_readers.return_value = [mock_reader]
    card_manager.connect()

    mock_connection.transmit.side_effect = [
        ([], 0x90, 0x00),
        ([], 0x90, 0x00),
        (list(der_cert), 0x90, 0x00),
    ]

    cert = card_manager.read_certificate(cert_type="auth")
    assert isinstance(cert, x509.Certificate)
    assert cert.serial_number == test_cert_and_key[0].serial_number

@patch('pyjpki.card.readers')
def test_certificate_caching(mock_readers, card_manager, test_cert_and_key):
    """Tests that certificates are cached after the first read."""
    _, _, der_cert = test_cert_and_key

    mock_reader = MagicMock()
    mock_connection = MagicMock()
    mock_reader.createConnection.return_value = mock_connection
    mock_readers.return_value = [mock_reader]
    card_manager.connect()

    mock_connection.transmit.side_effect = [
        ([], 0x90, 0x00),
        ([], 0x90, 0x00),
        (list(der_cert), 0x90, 0x00),
    ]

    cert1 = card_manager.read_certificate(cert_type="auth")
    assert mock_connection.transmit.call_count == 3

    cert2 = card_manager.read_certificate(cert_type="auth")
    assert mock_connection.transmit.call_count == 3
    assert cert1 == cert2

@patch('pyjpki.card.readers')
def test_get_certificate_info(mock_readers, card_manager, test_cert_and_key):
    """Tests the get_certificate_info method."""
    from pyjpki.certificate import JPKICertificate
    _, _, der_cert = test_cert_and_key

    mock_reader = MagicMock()
    mock_connection = MagicMock()
    mock_reader.createConnection.return_value = mock_connection
    mock_readers.return_value = [mock_reader]
    card_manager.connect()

    mock_connection.transmit.side_effect = [
        ([], 0x90, 0x00),
        ([], 0x90, 0x00),
        (list(der_cert), 0x90, 0x00),
    ]

    info = card_manager.get_certificate_info(cert_type="auth")
    assert isinstance(info, JPKICertificate)
    assert info.serial_number == test_cert_and_key[0].serial_number
    assert info.subject["CN"] == "test.example.com"

@patch('pyjpki.card.readers')
def test_sign_data(mock_readers, card_manager):
    """Tests the digital signature process."""
    from pyasn1.codec.der import decoder as der_decoder

    mock_reader = MagicMock()
    mock_connection = MagicMock()
    mock_reader.createConnection.return_value = mock_connection
    mock_readers.return_value = [mock_reader]
    card_manager.connect()

    fake_signature = b'\x01' * 256
    mock_connection.transmit.side_effect = [
        ([], 0x90, 0x00),
        ([], 0x90, 0x00),
        (list(fake_signature), 0x90, 0x00),
    ]

    data_to_sign = b"hello world"
    signature = card_manager.sign_data(data_to_sign, sign_type="auth")

    assert signature == fake_signature

    apdu_calls = mock_connection.transmit.call_args_list
    sign_apdu = apdu_calls[2].args[0]

    assert sign_apdu[0] == 0x80
    assert sign_apdu[1] == 0x2A

    lc = sign_apdu[4]
    der_data = bytes(sign_apdu[5:-1])
    assert lc == len(der_data)

    from pyasn1.type import univ, namedtype
    # Re-define the spec in the test to allow proper decoding
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

    decoded_digest_info, _ = der_decoder.decode(der_data, asn1Spec=DigestInfo())

    algo_oid = decoded_digest_info.getComponentByName('digestAlgorithm').getComponentByName('algorithm')
    digest = decoded_digest_info.getComponentByName('digest')

    assert algo_oid == OID_SHA256
    assert digest == hashlib.sha256(data_to_sign).digest()

@patch('pyjpki.card.readers')
def test_read_personal_info(mock_readers, card_manager):
    """Tests reading the 4 basic personal attributes."""
    from pyjpki.personal_info import JPKIPersonalInfo, TAG_NAME, TAG_ADDRESS, TAG_BIRTH_DATE, TAG_GENDER

    mock_reader = MagicMock()
    mock_connection = MagicMock()
    mock_reader.createConnection.return_value = mock_connection
    mock_readers.return_value = [mock_reader]
    card_manager.connect()

    name = "マイナンバー 太郎".encode('utf-8')
    addr = "東京都千代田区".encode('utf-8')
    bday = "20000101".encode('utf-8')
    gender = b'\x31'

    fake_tlv = (
        bytes(TAG_NAME) + bytes([len(name)]) + name +
        bytes(TAG_ADDRESS) + bytes([len(addr)]) + addr +
        bytes(TAG_BIRTH_DATE) + bytes([len(bday)]) + bday +
        bytes(TAG_GENDER) + bytes([len(gender)]) + gender
    )
    fake_tlv_with_header = b'\xFF\x20' + bytes([len(fake_tlv)]) + bytes([0xDF, 0x21]) + bytes([0x01, 0x00]) + fake_tlv

    mock_connection.transmit.side_effect = [
        ([], 0x90, 0x00),
        ([], 0x90, 0x00),
        (list(fake_tlv_with_header), 0x90, 0x00),
    ]

    info = card_manager.read_personal_info()

    assert isinstance(info, JPKIPersonalInfo)
    assert info.name == "マイナンバー 太郎"
    assert info.address == "東京都千代田区"
    assert info.birth_date == "20000101"
    assert info.gender == "Male"
