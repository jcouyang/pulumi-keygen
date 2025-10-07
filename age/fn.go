package age

import (
	"bytes"
	"context"
	"io"
	"strings"

	"filippo.io/age"
	"filippo.io/age/armor"
	"github.com/pulumi/pulumi-go-provider/infer"
)

type Encrypt struct{}

func (Encrypt) Invoke(_ context.Context, req infer.FunctionRequest[EncryptArgs]) (resp infer.FunctionResponse[EncryptResult], err error) {
	var recipients []age.Recipient
	for _, r := range req.Input.Recipients {
		parsed, err := age.ParseRecipients(strings.NewReader(r))
		if err != nil {
			return resp, err
		}
		recipients = append(recipients, parsed...)
	}
	
	out := &bytes.Buffer{}
	armorWriter := armor.NewWriter(out)
	defer armorWriter.Close()
	w, err := age.Encrypt(armorWriter, recipients...)
	defer w.Close()
	if err != nil {
		return resp, err
	}
	if _, err := io.WriteString(w, req.Input.Plaintext); err != nil {
		return resp, err
	}
	return infer.FunctionResponse[EncryptResult]{
		Output: EncryptResult{Result: out.String()},
	}, nil
}

func (r *Encrypt) Annotate(a infer.Annotator) {
	a.Describe(r,
		"Encrypt returns a copy of `s`, replacing matches of the `old`\n"+
			"with the replacement string `new`.")
}

type EncryptArgs struct {
	Recipients       []string `pulumi:"recipients"`
	Plaintext string `pulumi:"plaintext" provider:"secret"`
}

type EncryptResult struct {
	Result string `pulumi:"result"`
}


type Decrypt struct{}

func (Decrypt) Invoke(_ context.Context, req infer.FunctionRequest[DecryptArgs]) (resp infer.FunctionResponse[DecryptResult], err error) {	
	out := &bytes.Buffer{}
	armorReader := armor.NewReader(strings.NewReader(req.Input.Ciphertext))
	identity, err := age.ParseX25519Identity(req.Input.Identity)
	if err != nil {
		return resp, err
	}
	r, err := age.Decrypt(armorReader, identity)
	if err != nil {
		return resp, err
	}
	if _, err := io.Copy(out, r); err != nil {
		return resp, err
	}

	return infer.FunctionResponse[DecryptResult]{
		Output: DecryptResult{Result: out.String()},
	}, nil
}

func (r *Decrypt) Annotate(a infer.Annotator) {
	a.Describe(r,
		"Decrypt returns a copy of `s`, replacing matches of the `old`\n"+
			"with the replacement string `new`.")
}

type DecryptArgs struct {
	Identity       string `pulumi:"identity" provider:"secret"`
	Ciphertext string `pulumi:"ciphertext"`
}

type DecryptResult struct {
	Result string `pulumi:"result"`
}
