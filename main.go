package main

import (
	"context"
	"fmt"
	"os"

	"github.com/jcouyang/pulumi-keygen/age"
	"github.com/jcouyang/pulumi-keygen/awskms"
	"github.com/jcouyang/pulumi-keygen/config"
	"github.com/jcouyang/pulumi-keygen/encoding/pem"
	"github.com/jcouyang/pulumi-keygen/pkcs11"
	"github.com/pulumi/pulumi-go-provider/infer"
)

func main() {
	provider, err := infer.NewProviderBuilder().
		WithResources(
			infer.Resource(age.Identity{}),
			infer.Resource(awskms.Random{}),
			infer.Resource(awskms.DataKeyPair{}),
			infer.Resource(awskms.DataKey{}),
			infer.Resource(pkcs11.Key{}),
		).
		WithFunctions(
			infer.Function(&age.Encrypt{}),
			infer.Function(&age.Decrypt{}),
			infer.Function(&awskms.Encrypt{}),
			infer.Function(&awskms.Decrypt{}),
			infer.Function(&pkcs11.Encrypt{}),
			infer.Function(&pkcs11.Decrypt{}),
			infer.Function(&pem.Encode{}),
		).
		WithConfig(infer.Config(&config.Config{})).
		WithDescription("Cryptographic key generation and management").
		WithDisplayName("keygen").
		WithRepository("https://github.com/jcouyang/pulumi-keygen").
		WithKeywords("pulumi",
			"keygen",
			"encryption",
			"security",
			"cryptography",
			"age",
			"aws-kms",
			"pkcs11",
			"hsm").
		WithPublisher("jcouyang").
		WithLicense("BSD-3-Clause").
		Build()

	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %s", err.Error())
		os.Exit(1)
	}

	err = provider.Run(context.Background(), "keygen", "0.1.0")

	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %s", err.Error())
		os.Exit(1)
	}
}
