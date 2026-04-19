package main

import (
	"context"
	"fmt"
	"os"

	"github.com/jcouyang/pulumi-keygen/age"
	"github.com/jcouyang/pulumi-keygen/awskms"
	"github.com/jcouyang/pulumi-keygen/config"
	"github.com/jcouyang/pulumi-keygen/encoding/pem"
	"github.com/pulumi/pulumi-go-provider/infer"
)

var providerBuilder = infer.NewProviderBuilder()

func main() {
	provider, err := providerBuilder.
		WithResources(
			infer.Resource(age.Identity{}),
			infer.Resource(awskms.Random{}),
			infer.Resource(awskms.DataKeyPair{}),
			infer.Resource(awskms.DataKey{}),
		).
		WithFunctions(
			infer.Function(&age.Encrypt{}),
			infer.Function(&age.Decrypt{}),
			infer.Function(&awskms.Encrypt{}),
			infer.Function(&awskms.Decrypt{}),
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
