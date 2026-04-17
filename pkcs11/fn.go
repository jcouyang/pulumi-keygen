package pkcs11

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"fmt"

	"github.com/ThalesIgnite/crypto11"
	"github.com/jcouyang/pulumi-keygen/config"
	"github.com/pulumi/pulumi-go-provider/infer"
)

type Encrypt struct{}

func (Encrypt) Invoke(ctx context.Context, req infer.FunctionRequest[EncryptArgs]) (resp infer.FunctionResponse[EncryptResult], err error) {
	plaintext, err := base64.StdEncoding.DecodeString(req.Input.Plaintext)
	if err != nil {
		return resp, fmt.Errorf("failed to decode plaintext: %w", err)
	}

	c := infer.GetConfig[config.Config](ctx)
	// Configure crypto11 context
	config := &crypto11.Config{
		Path: c.HsmLocation,
		Pin:  c.HsmPin,
	}
	if len(req.Input.TokenLabel) > 0 {
		config.TokenLabel = req.Input.TokenLabel
	} else {
		config.SlotNumber = &req.Input.SlotNumber
	}

	ctx11, err := crypto11.Configure(config)
	if err != nil {
		return resp, fmt.Errorf("failed to configure PKCS#11: %w", err)
	}
	defer ctx11.Close()

	// Find the key by label
	key, err := ctx11.FindKeyPair(nil, []byte(req.Input.KeyLabel))
	if err != nil {
		return resp, fmt.Errorf("failed to find key with label %s: %w", req.Input.KeyLabel, err)
	}
	if key == nil {
		return resp, fmt.Errorf("key with label %s not found", req.Input.KeyLabel)
	}

	// Encrypt using the public key (standard Go crypto)
	pubKey := key.Public()

	var ciphertext []byte
	switch pub := pubKey.(type) {
	case *rsa.PublicKey:
		ciphertext, err = rsa.EncryptPKCS1v15(rand.Reader, pub, plaintext)
		if err != nil {
			return resp, fmt.Errorf("failed to encrypt with RSA: %w", err)
		}
	default:
		return resp, fmt.Errorf("unsupported key type for encryption: %T", pubKey)
	}

	return infer.FunctionResponse[EncryptResult]{
		Output: EncryptResult{Result: base64.StdEncoding.EncodeToString(ciphertext)},
	}, nil
}

func (r *Encrypt) Annotate(a infer.Annotator) {
	a.Describe(r, "Encrypt encrypts data using a key stored in a PKCS#11 HSM.")
}

type EncryptArgs struct {
	SlotNumber int    `pulumi:"slotNumber,optional"`
	TokenLabel string `pulumi:"tokenLabel,optional"`
	KeyLabel   string `pulumi:"keyLabel"`
	Plaintext  string `pulumi:"plaintext" provider:"secret"`
}

func (er *EncryptArgs) Annotate(a infer.Annotator) {
	a.Describe(&er.SlotNumber, "Slot number to use for the PKCS#11 session")
	a.Describe(&er.KeyLabel, "Label of the key to use for encryption")
	a.Describe(&er.Plaintext, "The plaintext to encrypt (base64-encoded)")
}

type EncryptResult struct {
	Result string `pulumi:"result"`
}

type Decrypt struct{}

func (d *Decrypt) Annotate(a infer.Annotator) {
	a.Describe(d, "Decrypt decrypts data using a key stored in a PKCS#11 HSM.")
}

func (Decrypt) Invoke(ctx context.Context, req infer.FunctionRequest[DecryptArgs]) (resp infer.FunctionResponse[DecryptResult], err error) {
	ciphertext, err := base64.StdEncoding.DecodeString(req.Input.Ciphertext)
	if err != nil {
		return resp, fmt.Errorf("failed to decode ciphertext: %w", err)
	}

	c := infer.GetConfig[config.Config](ctx)
	// Configure crypto11 context
	config := &crypto11.Config{
		Path: c.HsmLocation,
		Pin:  c.HsmPin,
	}

	if len(req.Input.TokenLabel) > 0 {
		config.TokenLabel = req.Input.TokenLabel
	} else {
		config.SlotNumber = &req.Input.SlotNumber
	}
	ctx11, err := crypto11.Configure(config)
	if err != nil {
		return resp, fmt.Errorf("failed to configure PKCS#11: %w", err)
	}
	defer ctx11.Close()

	// Find the key by label - need to cast to crypto.Decrypter
	signer, err := ctx11.FindKeyPair(nil, []byte(req.Input.KeyLabel))
	if err != nil {
		return resp, fmt.Errorf("failed to find key with label %s: %w", req.Input.KeyLabel, err)
	}
	if signer == nil {
		return resp, fmt.Errorf("key with label %s not found", req.Input.KeyLabel)
	}

	// Cast to SignerDecrypter which has Decrypt method
	decrypter, ok := signer.(crypto11.SignerDecrypter)
	if !ok {
		return resp, fmt.Errorf("key does not support decryption")
	}

	// Decrypt using the private key
	plaintext, err := decrypter.Decrypt(rand.Reader, ciphertext, nil)
	if err != nil {
		return resp, fmt.Errorf("failed to decrypt: %w", err)
	}

	return infer.FunctionResponse[DecryptResult]{
		Output: DecryptResult{Result: base64.StdEncoding.EncodeToString(plaintext)},
	}, nil
}

type DecryptArgs struct {
	TokenLabel string `pulumi:"tokenLabel"`
	SlotNumber int    `pulumi:"slotNumber,optional"`
	KeyLabel   string `pulumi:"keyLabel"`
	Ciphertext string `pulumi:"ciphertext"`
}

func (r *DecryptArgs) Annotate(a infer.Annotator) {
	a.Describe(&r.SlotNumber, "Slot number to use for the PKCS#11 session")
	a.Describe(&r.KeyLabel, "Label of the key to use for decryption")
	a.Describe(&r.Ciphertext, "The ciphertext to decrypt (base64-encoded)")
}

type DecryptResult struct {
	Result string `pulumi:"result"`
}
