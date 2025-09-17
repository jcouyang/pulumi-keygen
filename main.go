package main

import (
	"context"
	"fmt"
	"os"

	"github.com/pulumi/pulumi-go-provider/infer"
)

func main() {
	provider, err := infer.NewProviderBuilder().
		WithResources(
			infer.Resource(Age{}),
		).
		WithNamespace("github.com/jcouyang").
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
