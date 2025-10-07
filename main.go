package main

import (
	"context"
	"fmt"
	"os"

	"github.com/jcouyang/pulumi-keygen/age"
	"github.com/jcouyang/pulumi-keygen/awskms"
	"github.com/pulumi/pulumi-go-provider/infer"
)

func main() {
	provider, err := infer.NewProviderBuilder().
		WithResources(
			infer.Resource(age.Identity{}),
			infer.Resource(awskms.Random{}),
			infer.Resource(awskms.DataKeyPair{}),
		).
		WithFunctions(
			infer.Function(age.Encrypt{}),
			infer.Function(age.Decrypt{}),
		).
		WithNamespace("pulumi-resource-keygen").
		WithDisplayName("keygen").
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
