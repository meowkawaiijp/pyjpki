"""
This module defines data structures for holding parsed personal information.
"""
from dataclasses import dataclass
from typing import Dict, List

# Tags for the 4 basic attributes
TAG_HEADER = [0xDF, 0x21]
TAG_NAME = [0xDF, 0x22]
TAG_ADDRESS = [0xDF, 0x23]
TAG_BIRTH_DATE = [0xDF, 0x24]
TAG_GENDER = [0xDF, 0x25]

@dataclass
class JPKIPersonalInfo:
    """
    A dataclass to hold the 4 basic personal attributes from the card.
    """
    name: str
    address: str
    birth_date: str
    gender: str

    @classmethod
    def from_tlv_data(cls, tlv_data: bytes):
        """
        Parses TLV-encoded data to create a JPKIPersonalInfo instance.
        """
        parsed_tags = _parse_tlv(tlv_data)

        name = parsed_tags.get(bytes(TAG_NAME), b'').decode('utf-8', errors='ignore')
        address = parsed_tags.get(bytes(TAG_ADDRESS), b'').decode('utf-8', errors='ignore')
        birth_date = parsed_tags.get(bytes(TAG_BIRTH_DATE), b'').decode('utf-8', errors='ignore')

        gender_byte = parsed_tags.get(bytes(TAG_GENDER), b'\x33') # Default to 'Other'
        if gender_byte == b'\x31':
            gender = 'Male'
        elif gender_byte == b'\x32':
            gender = 'Female'
        else:
            gender = 'Other'

        return cls(
            name=name,
            address=address,
            birth_date=birth_date,
            gender=gender,
        )

def _parse_tlv(data: bytes) -> Dict[bytes, bytes]:
    """
    A simple TLV parser for the personal attribute data structure.
    """
    parsed_data = {}
    i = 0
    # Skip the container header (FF 20) and the length
    # Based on research, the actual data starts after the first few bytes.
    # A common pattern is a header like `FF 20 <length> DF 21 ...`
    # Let's find the first tag (DF 21)
    try:
        header_start = data.index(bytes(TAG_HEADER))
        i = header_start
    except ValueError:
        # If the header tag isn't found, we can't parse it.
        return {}

    while i < len(data):
        # Tag can be 1 or 2 bytes. For this specific data, it's 2 bytes (e.g., DF 21)
        tag = data[i:i+2]
        i += 2

        # Length can be 1 or 2 bytes
        if data[i] & 0x80: # Long form
            len_bytes = data[i] & 0x7F
            length = int.from_bytes(data[i+1:i+1+len_bytes], 'big')
            i += 1 + len_bytes
        else: # Short form
            length = data[i]
            i += 1

        value = data[i:i+length]
        parsed_data[tag] = value
        i += length

    return parsed_data
