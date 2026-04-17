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
