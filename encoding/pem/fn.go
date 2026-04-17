package pem

import (
	b "bytes"
	"context"
	"encoding/base64"
	"encoding/pem"

	"github.com/pulumi/pulumi-go-provider/infer"
)

type Encode struct{}

type EncodeArgs struct {
	Type    string            `pulumi:"type"`
	Headers map[string]string `pulumi:"header"`
	Bytes   string            `pulumi:"bytes"`
}
type EncodeResult struct {
	Result string `pulumi:"result"`
}

func (Encode) Invoke(ctx context.Context, req infer.FunctionRequest[EncodeArgs]) (resp infer.FunctionResponse[EncodeResult], err error) {
	bytes, err := base64.StdEncoding.DecodeString(req.Input.Bytes)
	if err != nil {
		return infer.FunctionResponse[EncodeResult]{}, err
	}
	block := &pem.Block{
		Type:    req.Input.Type,
		Headers: req.Input.Headers,
		Bytes:   bytes,
	}
	var buffer b.Buffer
	pem.Encode(&buffer, block)
	return infer.FunctionResponse[EncodeResult]{
		Output: EncodeResult{Result: string(buffer.Bytes())},
	}, nil
}
