---
title: Keygen Installation & Configuration
meta_desc: Information on how to install and configure the Keygen provider for Pulumi.
layout: package
---

# Keygen Provider Installation & Configuration

The Keygen provider enables you to generate and manage cryptographic keys using multiple backends including Age encryption, AWS KMS, and PKCS#11 HSMs.

## Installation

### Prerequisites

Before using the Keygen provider, ensure you have:

1. Installed Pulumi
2. Installed the required dependencies for your chosen backend:
   - For Age: No additional dependencies
   - For AWS KMS: AWS CLI configured with appropriate credentials
   - For PKCS#11: Appropriate HSM libraries and drivers

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

### Provider Configuration

The Keygen provider can be configured using the following options:

| Option | Required | Description |
|--------|----------|-------------|
| `hsmLocation` | Optional | HSM Library Location e.g. `/usr/lib/softhsm/libsofthsm2.so` |
| `hsmPin` | Optional | PIN for authentication to the PKCS#11 token |

### Authentication

Authentication requirements vary by backend:

#### Age
No authentication required. Keys are generated locally.

#### AWS KMS
Requires AWS credentials configured through:
- Environment variables (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`)
- AWS credentials file (`~/.aws/credentials`)
- IAM roles (when running on AWS)

Required IAM permissions:
- `kms:GenerateDataKey`
- `kms:GenerateDataKeyWithoutPlaintext`
- `kms:GenerateRandom`
- `kms:Encrypt`
- `kms:Decrypt`

#### PKCS#11
Requires:
- PKCS#11 library installed
- HSM or token initialized
- PIN for authentication

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

Or programmatically:

```typescript
import * as keygen from "@pulumi/pulumi-keygen";

const provider = new keygen.Provider("keygen", {
    hsmLocation: "/usr/lib/softhsm/libsofthsm2.so",
    hsmPin: process.env.HSM_PIN,
});
```
