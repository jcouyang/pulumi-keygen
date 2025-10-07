package awskms

import (
	"context"
	"encoding/base64"

	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	p "github.com/pulumi/pulumi-go-provider"
	"github.com/pulumi/pulumi-go-provider/infer"
)

type DataKeyPair struct{}

func (f *DataKeyPair) Annotate(a infer.Annotator) {
	a.Describe(&f, "Cryptographically secure random byte string")
}

type DataKeyPairArgs struct {
	ValidityPeriodHours int    `pulumi:"validityPeriodHours,optional"`
	EarlyRenewalHours   int    `pulumi:"earlyRenewalHours,optional"`
	KeyId  string `pulumi:"keyId"`
	KeyPairSpec types.DataKeyPairSpec `pulumi:"keyPairSpec"`
	WithoutPlainText bool `pulumi:"withoutPlainText,optional"`
}

func (f *DataKeyPairArgs) Annotate(a infer.Annotator) {
	// a.Describe(&f.SshPrivateKeyPem, "Optional, if provide will parse the key otherwise will generate an Ed25519 key")
}

type DataKeyPairState struct {
	DataKeyPairArgs
	PrivateKeyPlainText string `pulumi:"privateKey" provider:"secret"`
	PrivateKeyCiphertextBlob string `pulumi:"privateKeyCiphertextBlob"`
	PublicKey string `pulumi:"publicKey"`
	Created    int64  `pulumi:"created"`
}

func (f *DataKeyPairState) Annotate(a infer.Annotator) {
	// a.Describe(&f.ValidityPeriodHours, " how long this key valid for")
	// a.Describe(&f.EarlyRenewalHours, "")
}

func (r DataKeyPair) Create(ctx context.Context, req infer.CreateRequest[DataKeyPairArgs]) (resp infer.CreateResponse[DataKeyPairState], err error) {
	if req.DryRun {
		return
	}
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return
	}

	svc := kms.NewFromConfig(cfg)
	input := &kms.GenerateDataKeyPairInput{
		KeyId:             aws.String(req.Inputs.KeyId),
		KeyPairSpec:       req.Inputs.KeyPairSpec,
		DryRun:            aws.Bool(req.DryRun),
		EncryptionContext: map[string]string{},
	}
	if req.Inputs.WithoutPlainText {
		rresp, err := svc.GenerateDataKeyPairWithoutPlaintext(ctx, &kms.GenerateDataKeyPairWithoutPlaintextInput{
			KeyId: input.KeyId,
			KeyPairSpec: input.KeyPairSpec,
			DryRun: input.DryRun,
			EncryptionContext: input.EncryptionContext,
		})
			if err  != nil {
		return resp, err
	}
	
	return infer.CreateResponse[DataKeyPairState]{
		ID: req.Name, Output: DataKeyPairState{
			PrivateKeyCiphertextBlob: base64.StdEncoding.EncodeToString(rresp.PrivateKeyCiphertextBlob),
			DataKeyPairArgs:          req.Inputs,
			PublicKey:                base64.StdEncoding.EncodeToString(rresp.PublicKey),
			Created:                  time.Now().Unix(),
		},
	}, nil
	}
	
	rresp, err := svc.GenerateDataKeyPair(ctx, input)
	if err  != nil {
		return
	}
	
	return infer.CreateResponse[DataKeyPairState]{
		ID: req.Name, Output: DataKeyPairState{
		req.Inputs,
			base64.StdEncoding.EncodeToString(rresp.PrivateKeyPlaintext),
						base64.StdEncoding.EncodeToString(rresp.PrivateKeyCiphertextBlob),
						base64.StdEncoding.EncodeToString(rresp.PublicKey),
		time.Now().Unix(),
		},
	}, nil
}

func (DataKeyPair) Delete(ctx context.Context, req infer.DeleteRequest[DataKeyPairState]) (infer.DeleteResponse, error) {
	return infer.DeleteResponse{}, nil
}

func (DataKeyPair) Update(ctx context.Context, req infer.UpdateRequest[DataKeyPairArgs, DataKeyPairState]) (infer.UpdateResponse[DataKeyPairState], error) {
	if req.DryRun {
		return infer.UpdateResponse[DataKeyPairState]{}, nil
	}
	return infer.UpdateResponse[DataKeyPairState]{
		Output: DataKeyPairState{
			req.Inputs,
			req.State.PrivateKeyPlainText,
			req.State.PrivateKeyCiphertextBlob,
			req.State.PublicKey,
			req.State.Created,
		},
	}, nil
}

func (DataKeyPair) Diff(ctx context.Context, req infer.DiffRequest[DataKeyPairArgs, DataKeyPairState]) (infer.DiffResponse, error) {
	diff := map[string]p.PropertyDiff{}
	if req.Inputs.EarlyRenewalHours != req.State.EarlyRenewalHours {
		diff["earlyRenewalHours"] = p.PropertyDiff{Kind: p.Update}
	}
	if req.Inputs.ValidityPeriodHours != req.State.ValidityPeriodHours {
		diff["validityPeriodHours"] = p.PropertyDiff{Kind: p.Update}
	}

	if req.Inputs.KeyPairSpec != req.State.KeyPairSpec {
		diff["keyPairSpec"] = p.PropertyDiff{Kind: p.UpdateReplace}
	}
	if req.Inputs.KeyId != req.State.KeyId {
		diff["keyId"] = p.PropertyDiff{Kind: p.UpdateReplace}
	}
	if req.Inputs.ValidityPeriodHours != 0 &&
		time.Now().Unix() >=
			req.State.Created+int64(req.Inputs.ValidityPeriodHours-req.Inputs.EarlyRenewalHours)*60*60 {
		diff["expired"] = p.PropertyDiff{Kind: p.UpdateReplace}
		p.GetLogger(ctx).Warningf("key %s is about to expire, will be replaced if perform this update!", req.ID)
	}
	return infer.DiffResponse{
		DeleteBeforeReplace: false,
		HasChanges:          len(diff) > 0,
		DetailedDiff:        diff,
	}, nil
}

func (DataKeyPair) WireDependencies(f infer.FieldSelector, args *DataKeyPairArgs, state *DataKeyPairState) {
	f.OutputField(&state.PrivateKeyCiphertextBlob).DependsOn(f.InputField(&args.ValidityPeriodHours))
	f.OutputField(&state.PrivateKeyCiphertextBlob).DependsOn(f.InputField(&args.EarlyRenewalHours))
	f.OutputField(&state.PrivateKeyCiphertextBlob).DependsOn(f.InputField(&args.KeyId))
}
