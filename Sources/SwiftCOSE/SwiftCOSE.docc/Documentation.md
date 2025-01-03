# ``SwiftCOSE``

A Swift implementation of CBOR Object Signing and Encryption

## What is COSE?

CBOR Object Signing and Encryption (COSE) is a data format designed for the concise representation of small messages, optimized for low-power devices. COSE messages can be encrypted, authenticated (MAC'ed), and signed. A basic COSE message structure includes:

- **Protected header**: Contains information that needs protection during encryption, MAC calculation, or signing.
- **Unprotected header**: Contains information not protected by cryptographic algorithms.
- **Payload**: The message content, protected by cryptographic algorithms.

![Basic Structure](../images/basic_structure.png)

### Types of COSE Messages

There are six different types of COSE messages:

- **Encrypt0**: An encrypted message with a single recipient, protected by a shared Content Encryption Key (CEK).
- **Encrypt**: An encrypted message with multiple recipients, each having the CEK encrypted with a Key Encryption Key (KEK) using AES key wrap.
- **MAC0**: An authenticated message with one recipient.
- **MAC**: An authenticated message with multiple recipients, each having the authentication key encrypted with a KEK.
- **Sign1**: A signed message with a single signature.
- **Sign**: A signed message with multiple signatures, each carried in a COSE signature structure.

Based on the message type, additional fields are appended to the basic COSE structure:

- A single *MAC* or *signature* field for **MAC0** or **Sign1** messages.
- A list of *COSE recipients* or *COSE signatures* for **MAC**, **Encrypt**, and **Sign** messages.

### COSE Key Objects

The RFC defines COSE Key objects used to store and transport cryptographic keys. The main key types are:

- **EC2**: Elliptic Curve Keys with an x/y-coordinate pair.
- **OKP**: Octet Key Pair.
- **Symmetric**: Symmetric Keys for symmetric cryptography.

## Table of Contents

### The SwiftCOSE Package (API)

- [Messages](pycose/messages/index.rst)
- [Keys](pycose/keys/index.rst)
- [Algorithms](pycose/algorithms.rst)

### Miscellaneous

- [Installation](installation.rst)
- [License](LICENSE.rst)
- [Contributing](CONTRIBUTING.rst)
- [Examples](examples.rst)
- [Glossary](glossary.rst)

For more details on COSE, refer to the [RFC 8152](https://tools.ietf.org/html/rfc8152).
