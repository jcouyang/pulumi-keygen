package awskms

import (
	"context"
	"encoding/base64"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/pulumi/pulumi-go-provider/infer"
)

type Encrypt struct{}

func (Encrypt) Invoke(ctx context.Context, req infer.FunctionRequest[EncryptArgs]) (resp infer.FunctionResponse[EncryptResult], err error) {
	plaintext, err := base64.StdEncoding.DecodeString(req.Input.Plaintext)
	if err != nil {
		return
	}

	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return
	}

	svc := kms.NewFromConfig(cfg)
	input := &kms.EncryptInput{
		KeyId:               aws.String(req.Input.KeyId),
		EncryptionAlgorithm: types.EncryptionAlgorithmSpec(req.Input.EncryptionAlgorithm),
		Plaintext:           plaintext,
	}
	out, err := svc.Encrypt(ctx, input)
	if err != nil {
		return
	}

	return infer.FunctionResponse[EncryptResult]{
		Output: EncryptResult{Result: base64.StdEncoding.EncodeToString(out.CiphertextBlob)},
	}, nil
}

func (r *Encrypt) Annotate(a infer.Annotator) {
	a.Describe(r, "Encrypt encrypts a file to one or more recipients.")
}

type EncryptArgs struct {
	KeyId               string `pulumi:"keyId"`
	EncryptionAlgorithm string `pulumi:"encryptionAlgorithm,optional"`
	Plaintext           string `pulumi:"plaintext" provider:"secret"`
}

func (er *EncryptArgs) Annotate(a infer.Annotator) {
	a.Describe(&er.Plaintext, "The plaintext to encrypt. Base64-encoded binary data object")
	a.Describe(&er.EncryptionAlgorithm, "The encryption algorithm to use. SYMMETRIC_DEFAULT | RSAES_OAEP_SHA_1 | RSAES_OAEP_SHA_256 | SM2PKE")
	a.Describe(&er.KeyId, "Identifies the KMS key to use in the encryption operation")
}

type EncryptResult struct {
	Result string `pulumi:"result"`
}

type Decrypt struct{}

func (Decrypt) Annotate(a infer.Annotator) {
	a.Describe(Decrypt{}, "Decrypt decrypts a file encrypted to one or more identities.")
}

func (Decrypt) Invoke(ctx context.Context, req infer.FunctionRequest[DecryptArgs]) (resp infer.FunctionResponse[DecryptResult], err error) {
	ciphertext, err := base64.StdEncoding.DecodeString(req.Input.Ciphertext)
	if err != nil {
		return
	}

	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return
	}

	svc := kms.NewFromConfig(cfg)
	input := &kms.DecryptInput{
		CiphertextBlob: ciphertext,
	}

	out, err := svc.Decrypt(ctx, input)
	if err != nil {
		return
	}
	return infer.FunctionResponse[DecryptResult]{
		Output: DecryptResult{Result: base64.StdEncoding.EncodeToString(out.Plaintext)},
	}, nil
}

type DecryptArgs struct {
	Ciphertext string `pulumi:"ciphertext"`
}

func (r *DecryptArgs) Annotate(a infer.Annotator) {
	a.Describe(&r.Ciphertext, "The ciphertext to decrypt.")
}

type DecryptResult struct {
	Result string `pulumi:"result"`
}
