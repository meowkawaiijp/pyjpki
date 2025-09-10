# pyjpki

A Python module for interacting with Japanese Public Key Infrastructure (JPKI) smart cards, such as the My Number Card.

This library provides a simple, high-level API to perform common operations like PIN verification, certificate reading, digital signing, and reading personal attributes from the card.

## Features

- List available smart card readers.
- Connect to and disconnect from a card.
- Verify User Authentication PIN, Signing PIN, and Attribute Reading PIN.
- Read authentication and signing certificates from the card.
- Parse certificate information (Subject, Issuer, Validity, etc.).
- Create digital signatures (SHA256withRSA) using the card's private keys.
- Read the 4 basic personal attributes (Name, Address, DOB, Gender).
- Utility functions for certificate validation and PEM conversion.
- Detailed debug logging of all APDU commands.

## Installation

This project uses [Poetry](https://python-poetry.org/) for dependency management.

First, ensure you have the necessary PC/SC drivers installed for your operating system. On Debian/Ubuntu, you can install the development headers with:
```bash
sudo apt-get update
sudo apt-get install -y libpcsclite-dev
```

Then, install the library and its dependencies:
```bash
pip install .
```

## Basic Usage

Here are some examples of how to use the `pyjpki` library.

### Connecting to a Card and Verifying a PIN

```python
import logging
from pyjpki import CardManager, PinVerificationError

# Enable debug logging to see APDU commands
logging.basicConfig(level=logging.INFO)
logging.getLogger("pyjpki").setLevel(logging.DEBUG)

try:
    # Use as a context manager for automatic connection/disconnection
    with CardManager() as manager:
        print("Successfully connected to card.")

        # Verify the 4-digit PIN for reading personal attributes
        pin = "1234"
        try:
            manager.verify_pin(pin, pin_type="attr")
            print("Attribute PIN verification successful.")
        except PinVerificationError as e:
            print(f"PIN verification failed. Retries left: {e.retries_left}")

except Exception as e:
    print(f"An error occurred: {e}")
```

### Reading a Certificate

```python
from pyjpki import CardManager

with CardManager() as manager:
    # Read the authentication certificate
    auth_cert_info = manager.get_certificate_info(cert_type="auth")

    print("--- Authentication Certificate ---")
    print(f"Subject: {auth_cert_info.subject}")
    print(f"Issuer: {auth_cert_info.issuer}")
    print(f"Serial Number: {auth_cert_info.serial_number}")
    print(f"Valid From: {auth_cert_info.not_valid_before}")
    print(f"Valid Until: {auth_cert_info.not_valid_after}")
```

### Creating a Digital Signature

```python
from pyjpki import CardManager, PinVerificationError

with CardManager() as manager:
    # Signing requires the corresponding PIN to be verified first
    auth_pin = "1234" # Replace with your actual PIN
    try:
        manager.verify_pin(auth_pin, pin_type="auth")
        print("Authentication PIN verified.")

        data_to_sign = b"This is a test message."
        signature = manager.sign_data(data_to_sign, sign_type="auth")

        print(f"\nData: {data_to_sign}")
        print(f"Signature (hex): {signature.hex()}")

    except PinVerificationError as e:
        print(f"PIN verification failed. Retries left: {e.retries_left}")
```

### Reading Personal Information

```python
from pyjpki import CardManager, PinVerificationError

with CardManager() as manager:
    # Reading attributes requires the 4-digit PIN to be verified first
    attr_pin = "1234" # Replace with your actual PIN
    try:
        manager.verify_pin(attr_pin, pin_type="attr")
        print("Attribute PIN verified.")

        info = manager.read_personal_info()

        print("\n--- Personal Information ---")
        print(f"Name: {info.name}")
        print(f"Address: {info.address}")
        print(f"Date of Birth: {info.birth_date}")
        print(f"Gender: {info.gender}")

    except PinVerificationError as e:
        print(f"PIN verification failed. Retries left: {e.retries_left}")
```
