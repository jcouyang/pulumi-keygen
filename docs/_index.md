---
title: Keygen
meta_desc: Provides access to cryptographic key generation and management via Age, AWS KMS, and PKCS#11 HSMs.
layout: package
---

# Keygen Provider

The Keygen provider enables you to generate and manage cryptographic keys using multiple backends including Age encryption, AWS KMS, and PKCS#11 HSMs.

## Features

The Keygen provider supports:

- **Age Encryption**: Modern encryption using X25519 keys for file encryption and secrets management
- **AWS KMS Integration**: Cloud-based key management with AWS Key Management Service
- **PKCS#11 HSM Support**: Hardware Security Module integration for high-security key storage

## Installing

### Installing the Provider

To install the Keygen provider, use the following command:

```bash
pulumi plugin install resource keygen <version> --server github://api.github.com/jcouyang
```

### Installing the SDK

The Keygen provider supports multiple programming languages through its SDKs:

#### JavaScript/TypeScript

```bash
npm install @pulumi/pulumi-keygen
```

#### Python

```bash
pip install pulumi_keygen
```

#### Go

```bash
go get github.com/jcouyang/pulumi-keygen/sdk/go/keygen
```

#### .NET

```bash
dotnet add package Pulumi.Keygen
```

#### Java

Add the following dependency to your `pom.xml`:

```xml
<dependency>
    <groupId>com.pulumi</groupId>
    <artifactId>keygen</artifactId>
    <version>[version]</version>
</dependency>
```

## Configuration

The Keygen provider can be configured using the following options:

### Provider Configuration

- `hsmLocation`: HSM Library Location e.g. `/usr/lib/softhsm/libsofthsm2.so`
- `hsmPin`: PIN for authentication to the PKCS#11 token (secret)

### Example Configuration

```yaml
# Pulumi.yaml
resources:
  provider:
    type: pulumi:providers:keygen
    properties:
      hsmLocation: /usr/lib/softhsm/libsofthsm2.so
      hsmPin: ${HSM_PIN}
```

## Usage Examples

### Age Identity Generation

```typescript
import * as age from "@pulumi/pulumi-keygen/age";

const identity = new age.Identity("my-identity", {
    validityPeriodHours: 8760,  // 1 year
    earlyRenewalHours: 720,     // 30 days before expiration
});

export const publicKey = identity.recipient;
export const privateKey = identity.privateKey;
```

### AWS KMS Random Bytes Generation

```typescript
import * as awskms from "@pulumi/pulumi-keygen/awskms";

const random = new awskms.Random("my-random", {
    numberOfBytes: 32,
    validityPeriodHours: 8760,
    earlyRenewalHours: 720,
});

export const randomBytes = random.plaintext;
```

### PKCS#11 Key Generation

```typescript
import * as pkcs11 from "@pulumi/pulumi-keygen/pkcs11";

const hsmKey = new pkcs11.Key("my-hsm-key", {
    modulePath: "/usr/lib/softhsm/libsofthsm2.so",
    pin: "1234",
    keyLabel: "my-application-key",
    keyType: "RSA",
    keySize: 2048,
    validityPeriodHours: 8760,
    earlyRenewalHours: 720,
});

export const publicKey = hsmKey.publicKey;
```

## Functions

The Keygen provider also offers functions for encryption and decryption operations:

### Age Encryption

```typescript
const encrypted = age.encrypt({
    recipients: [identity.recipient],
    plaintext: "Hello, World!",
});
```

### AWS KMS Encryption

```typescript
const encrypted = awskms.encrypt({
    keyId: "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012",
    plaintext: Buffer.from("Hello, World!").toString("base64"),
});
```

### PKCS#11 Encryption

```typescript
const encrypted = pkcs11.encrypt({
    modulePath: "/usr/lib/softhsm/libsofthsm2.so",
    pin: "1234",
    keyLabel: "my-application-key",
    plaintext: Buffer.from("Hello, World!").toString("base64"),
});
```
