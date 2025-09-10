import pytest
from pyjpki.personal_info import JPKIPersonalInfo, _parse_tlv, TAG_NAME, TAG_ADDRESS, TAG_BIRTH_DATE, TAG_GENDER

def test_parse_tlv_normal():
    """Tests the TLV parser with a normal, well-formed byte string."""
    name = "マイナンバー 太郎".encode('utf-8')
    addr = "東京都千代田区".encode('utf-8')
    bday = "20000101".encode('utf-8')
    gender = b'\x31' # Male

    # Header + Tag + Length + Value
    fake_tlv = (
        b'\xFF\x20\xAB' + # Fake container header
        bytes([0xDF, 0x21, 0x01, 0x00]) + # Header tag
        bytes(TAG_NAME) + bytes([len(name)]) + name +
        bytes(TAG_ADDRESS) + bytes([len(addr)]) + addr +
        bytes(TAG_BIRTH_DATE) + bytes([len(bday)]) + bday +
        bytes(TAG_GENDER) + bytes([len(gender)]) + gender
    )

    parsed = _parse_tlv(fake_tlv)

    assert parsed[bytes(TAG_NAME)] == name
    assert parsed[bytes(TAG_ADDRESS)] == addr
    assert parsed[bytes(TAG_BIRTH_DATE)] == bday
    assert parsed[bytes(TAG_GENDER)] == gender

def test_from_tlv_data():
    """Tests the full parsing and dataclass creation."""
    name = "Mynumber Taro".encode('utf-8')
    addr = "Tokyo".encode('utf-8')
    bday = "20000101".encode('utf-8')
    gender = b'\x32' # Female

    fake_tlv = (
        b'\xFF\x20\xAB' +
        bytes([0xDF, 0x21, 0x01, 0x00]) +
        bytes(TAG_NAME) + bytes([len(name)]) + name +
        bytes(TAG_ADDRESS) + bytes([len(addr)]) + addr +
        bytes(TAG_BIRTH_DATE) + bytes([len(bday)]) + bday +
        bytes(TAG_GENDER) + bytes([len(gender)]) + gender
    )

    info = JPKIPersonalInfo.from_tlv_data(fake_tlv)

    assert info.name == "Mynumber Taro"
    assert info.address == "Tokyo"
    assert info.birth_date == "20000101"
    assert info.gender == "Female"

def test_parse_tlv_missing_tag():
    """Tests that the parser handles missing tags gracefully."""
    name = "Test Name".encode('utf-8')
    fake_tlv = (
        b'\xFF\x20\xAB' +
        bytes([0xDF, 0x21, 0x01, 0x00]) +
        bytes(TAG_NAME) + bytes([len(name)]) + name
    )

    info = JPKIPersonalInfo.from_tlv_data(fake_tlv)
    assert info.name == "Test Name"
    assert info.address == "" # Should default to empty string
    assert info.gender == "Other" # Should default to other

def test_parse_tlv_empty_input():
    """Tests that the parser handles empty input without crashing."""
    info = JPKIPersonalInfo.from_tlv_data(b'')
    assert info.name == ""
    assert info.address == ""
    assert info.birth_date == ""
    assert info.gender == "Other"
