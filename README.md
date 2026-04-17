---
title: Keygen
meta_desc: A Pulumi provider for cryptographic key generation and management supporting Age encryption, AWS KMS, and PKCS#11 HSMs.
layout: package
---
# Pulumi Keygen Provider

A Pulumi provider for cryptographic key generation and management. Supports Age encryption, AWS KMS, and PKCS#11 HSMs.

## Table of Contents

- [Overview](#overview)
- [Installation](#installation)
- [Providers](#providers)
  - [Age](#age-provider)
  - [AWS KMS](#aws-kms-provider)
  - [PKCS#11](#pkcs11-provider)
- [Building](#building)

## Overview

pulumi-keygen provides multiple cryptographic key providers:

| Provider | Description | Use Case |
|----------|-------------|----------|
| **Age** | Modern encryption using X25519 | File encryption, secrets management |
| **AWS KMS** | AWS Key Management Service integration | Cloud key management, compliance |
| **PKCS#11** | Hardware Security Module (HSM) support | High-security key storage |

## Installation

```bash
pulumi plugin install keygen
```

## Providers

### Age Provider

The Age provider implements the [Age encryption protocol](https://age-encryption.org/), a modern, simple, and secure file encryption tool.

#### Resources

##### `age.Identity`

Generates an Age encryption identity (X25519 key pair).

```typescript
import * as age from "@pulumi/pulumi-keygen/age";

const identity = new age.Identity("my-identity", {
    // Optional: Custom random bytes (32 bytes, base64 encoded)
    random: "base64-encoded-random-bytes",
    
    // Optional: Key rotation settings
    validityPeriodHours: 8760,  // 1 year
    earlyRenewalHours: 720,     // 30 days before expiration
});

export const publicKey = identity.recipient;  // Age recipient (public key)
export const privateKey = identity.privateKey;  // Secret key
```

**Arguments:**

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `random` | string | No | Custom random bytes (32 bytes, base64) |
| `validityPeriodHours` | int | No | Key validity period |
| `earlyRenewalHours` | int | No | Hours before expiration to renew |

**Attributes:**

| Name | Type | Description |
|------|------|-------------|
| `recipient` | string | Age recipient (public key) |
| `privateKey` | string | Age identity (secret) |
| `created` | int | Unix timestamp of creation |

#### Functions

##### `age.encrypt`

Encrypts data to one or more Age recipients.

```typescript
const encrypted = age.encrypt({
    recipients: [identity.recipient],
    plaintext: "Hello, World!",
});

// encrypted.result contains the encrypted message in Age armor format
```

**Arguments:**

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `recipients` | string[] | Yes | List of Age recipient public keys |
| `plaintext` | string | Yes | Plaintext to encrypt |

**Returns:**

| Name | Type | Description |
|------|------|-------------|
| `result` | string | Encrypted message (Age armor format) |

##### `age.decrypt`

Decrypts data using an Age identity.

```typescript
const decrypted = age.decrypt({
    identity: identity.privateKey,
    ciphertext: encrypted.result,
});

// decrypted.result contains the original plaintext
```

**Arguments:**

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `identity` | string | Yes | Age identity (private key) |
| `ciphertext` | string | Yes | Age-encrypted message |

**Returns:**

| Name | Type | Description |
|------|------|-------------|
| `result` | string | Decrypted plaintext |

---

### AWS KMS Provider

The AWS KMS provider integrates with [AWS Key Management Service](https://aws.amazon.com/kms/) for cloud-based key management.

#### Prerequisites

- AWS account with KMS access
- AWS credentials configured (environment variables, `~/.aws/credentials`, or IAM role)
- Required IAM permissions:
  - `kms:GenerateDataKey`
  - `kms:GenerateDataKeyWithoutPlaintext`
  - `kms:GenerateRandom`
  - `kms:Encrypt`
  - `kms:Decrypt`

#### Resources

##### `awskms.Random`

Generates cryptographically secure random bytes using AWS KMS.

```typescript
import * as awskms from "@pulumi/pulumi-keygen/awskms";

const random = new awskms.Random("my-random", {
    numberOfBytes: 32,
    
    // Optional: Use custom key store
    customKeyStoreId: "cks-1234567890abcdef0",
    
    // Optional: Key rotation settings
    validityPeriodHours: 8760,
    earlyRenewalHours: 720,
});

export const randomBytes = random.plaintext;  // Base64-encoded random bytes
```

**Arguments:**

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `numberOfBytes` | int | Yes | Number of random bytes to generate (1-1024) |
| `customKeyStoreId` | string | No | Custom key store ID |
| `validityPeriodHours` | int | No | Validity period |
| `earlyRenewalHours` | int | No | Early renewal period |

**Attributes:**

| Name | Type | Description |
|------|------|-------------|
| `plaintext` | string | Base64-encoded random bytes (secret) |
| `created` | int | Unix timestamp of creation |

##### `awskms.DataKey`

Generates a symmetric data key for use outside of AWS KMS.

```typescript
const dataKey = new awskms.DataKey("my-data-key", {
    keyId: "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012",
    keySpec: "AES_256",  // or "AES_128"
    
    // Optional: Generate without plaintext (for later decryption)
    withoutPlainText: false,
    
    // Optional: Key rotation settings
    validityPeriodHours: 8760,
    earlyRenewalHours: 720,
});

export const plaintextKey = dataKey.plaintext;      // Secret key material
export const encryptedKey = dataKey.ciphertextBlob; // Encrypted under KMS key
```

**Arguments:**

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `keyId` | string | Yes | KMS key ID or ARN |
| `keySpec` | string | Yes | "AES_128" or "AES_256" |
| `withoutPlainText` | bool | No | Generate without plaintext |
| `validityPeriodHours` | int | No | Validity period |
| `earlyRenewalHours` | int | No | Early renewal period |

**Attributes:**

| Name | Type | Description |
|------|------|-------------|
| `plaintext` | string | Plaintext key material (secret) |
| `ciphertextBlob` | string | Encrypted key material |
| `created` | int | Unix timestamp of creation |

##### `awskms.DataKeyPair`

Generates an asymmetric data key pair.

```typescript
const keyPair = new awskms.DataKeyPair("my-key-pair", {
    keyId: "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012",
    keyPairSpec: "RSA_2048",  // or "RSA_3072", "RSA_4096", "ECC_NIST_P256", etc.
    
    // Optional: Key rotation settings
    validityPeriodHours: 8760,
    earlyRenewalHours: 720,
});

export const publicKey = keyPair.publicKey;           // Public key
export const privateKeyPlaintext = keyPair.privateKeyPlaintext;  // Secret private key
export const privateKeyCiphertext = keyPair.privateKeyCiphertext; // Encrypted private key
```

**Arguments:**

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `keyId` | string | Yes | KMS key ID or ARN |
| `keyPairSpec` | string | Yes | Key pair specification |
| `validityPeriodHours` | int | No | Validity period |
| `earlyRenewalHours` | int | No | Early renewal period |

**Attributes:**

| Name | Type | Description |
|------|------|-------------|
| `publicKey` | string | Public key (base64) |
| `privateKeyPlaintext` | string | Private key plaintext (secret) |
| `privateKeyCiphertext` | string | Private key encrypted under KMS key |
| `created` | int | Unix timestamp of creation |

#### Functions

##### `awskms.encrypt`

Encrypts plaintext using AWS KMS.

```typescript
const encrypted = awskms.encrypt({
    keyId: "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012",
    encryptionAlgorithm: "SYMMETRIC_DEFAULT",  // Optional
    plaintext: Buffer.from("Hello, World!").toString("base64"),
});

// encrypted.result contains base64-encoded ciphertext
```

**Arguments:**

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `keyId` | string | Yes | KMS key ID or ARN |
| `plaintext` | string | Yes | Base64-encoded plaintext |
| `encryptionAlgorithm` | string | No | Algorithm (default: "SYMMETRIC_DEFAULT") |

**Returns:**

| Name | Type | Description |
|------|------|-------------|
| `result` | string | Base64-encoded ciphertext |

##### `awskms.decrypt`

Decrypts ciphertext using AWS KMS.

```typescript
const decrypted = awskms.decrypt({
    ciphertext: encrypted.result,
});

// decrypted.result contains base64-encoded plaintext
```

**Arguments:**

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `ciphertext` | string | Yes | Base64-encoded ciphertext |

**Returns:**

| Name | Type | Description |
|------|------|-------------|
| `result` | string | Base64-encoded plaintext |

---

### PKCS#11 Provider

The PKCS#11 provider enables integration with Hardware Security Modules (HSMs) via the [PKCS#11 standard](https://en.wikipedia.org/wiki/PKCS_11).

#### Requirements

**Build Requirements:**

PKCS#11 requires CGO to be enabled:

```bash
export CGO_ENABLED=1
```

You need a C compiler and PKCS#11 libraries:

**Ubuntu/Debian:**
```bash
sudo apt-get install gcc pkg-config libssl-dev softhsm2
```

**RHEL/CentOS/Fedora:**
```bash
sudo yum install gcc pkgconfig openssl-devel softhsm
```

**macOS:**
```bash
brew install pkg-config openssl softhsm
```

#### Resources

##### `pkcs11.Key`

Manages a cryptographic key stored in an HSM.

```typescript
import * as pkcs11 from "@pulumi/pulumi-keygen/pkcs11";

const hsmKey = new pkcs11.Key("my-hsm-key", {
    // Required: Path to PKCS#11 module
    modulePath: "/usr/lib/softhsm/libsofthsm2.so",
    
    // Required: PIN for HSM authentication
    pin: "1234",
    
    // Required: Label for the key
    keyLabel: "my-application-key",
    
    // Optional: Slot number (defaults to first available)
    slotNumber: 0,
    
    // Optional: Key type - "RSA" or "EC" (default: "RSA")
    keyType: "RSA",
    
    // Optional: Key size in bits (default: 2048)
    // RSA: 2048, 3072, 4096
    // EC: 256 (P-256), 384 (P-384), 521 (P-521)
    keySize: 2048,
    
    // Optional: Key rotation settings
    validityPeriodHours: 8760,  // 1 year
    earlyRenewalHours: 720,     // 30 days before expiration
});
```

**Arguments:**

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `modulePath` | string | Yes | Path to PKCS#11 shared library |
| `pin` | string | Yes | PIN for HSM authentication (secret) |
| `keyLabel` | string | Yes | Label for the key in HSM |
| `slotNumber` | int | No | Token slot number |
| `keyType` | string | No | "RSA" or "EC" (default: "RSA") |
| `keySize` | int | No | Key size in bits (default: 2048) |
| `validityPeriodHours` | int | No | Key validity period |
| `earlyRenewalHours` | int | No | Hours before expiration to renew |

**Attributes:**

| Name | Type | Description |
|------|------|-------------|
| `publicKey` | string | Base64-encoded public key (PKIX format) |
| `created` | int | Unix timestamp of key creation |

#### Functions

##### `pkcs11.encrypt`

Encrypts data using an HSM-stored key's public key.

```typescript
const encrypted = pkcs11.encrypt({
    modulePath: "/usr/lib/softhsm/libsofthsm2.so",
    slotNumber: 0,
    pin: "1234",
    keyLabel: "my-application-key",
    plaintext: Buffer.from("Hello, World!").toString("base64"),
});
```

**Arguments:**

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `modulePath` | string | Yes | Path to PKCS#11 shared library |
| `pin` | string | Yes | PIN for HSM authentication (secret) |
| `keyLabel` | string | Yes | Label of the encryption key |
| `plaintext` | string | Yes | Base64-encoded plaintext (secret) |
| `slotNumber` | int | No | Token slot number |

**Returns:**

| Name | Type | Description |
|------|------|-------------|
| `result` | string | Base64-encoded ciphertext |

##### `pkcs11.decrypt`

Decrypts data using an HSM-stored key's private key.

```typescript
const decrypted = pkcs11.decrypt({
    modulePath: "/usr/lib/softhsm/libsofthsm2.so",
    slotNumber: 0,
    pin: "1234",
    keyLabel: "my-application-key",
    ciphertext: encrypted.result,
});
```

**Arguments:**

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `modulePath` | string | Yes | Path to PKCS#11 shared library |
| `pin` | string | Yes | PIN for HSM authentication (secret) |
| `keyLabel` | string | Yes | Label of the decryption key |
| `ciphertext` | string | Yes | Base64-encoded ciphertext |
| `slotNumber` | int | No | Token slot number |

**Returns:**

| Name | Type | Description |
|------|------|-------------|
| `result` | string | Base64-encoded plaintext |

#### Testing with SoftHSM2

SoftHSM2 is a software implementation of an HSM for testing:

1. **Install SoftHSM2:**
   ```bash
   # Ubuntu/Debian
   sudo apt-get install softhsm2
   
   # macOS
   brew install softhsm
   ```

2. **Initialize a Token:**
   ```bash
   softhsm2-util --init-token --slot 0 --label "test-token" --so-pin 1234 --pin 1234
   ```

3. **Configure Environment:**
   ```bash
   export SOFTHSM2_CONF=/etc/softhsm/softhsm2.conf
   ```

4. **Find Module Path:**
   ```bash
   softhsm2-util --show-config
   ```

#### Supported HSMs

- **SoftHSM2** - Software HSM for testing
- **AWS CloudHSM** - Cloud-based HSM service
- **SafeNet Luna** - Network HSM
- **Thales nShield** - Enterprise HSM
- **YubiHSM** - USB HSM

---

## Building

### Standard Build

```bash
go build -o pulumi-resource-keygen
```

### Build with PKCS#11 Support

```bash
export CGO_ENABLED=1
go build -o pulumi-resource-keygen
```

### Using Nix

```bash
nix-shell
go build
```

## License

MIT License - See [LICENSE](LICENSE) for details.
