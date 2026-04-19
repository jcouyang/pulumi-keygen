//go:build cgo
// +build cgo

package main

import (
	"github.com/jcouyang/pulumi-keygen/pkcs11"
	"github.com/pulumi/pulumi-go-provider/infer"
)

func init() {
	providerBuilder = providerBuilder.
		WithResources(
			infer.Resource(pkcs11.Key{}),
		).
		WithFunctions(
			infer.Function(&pkcs11.Encrypt{}),
			infer.Function(&pkcs11.Decrypt{}),
		)
}
