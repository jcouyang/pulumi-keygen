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

type DataKey struct{}

func (f *DataKey) Annotate(a infer.Annotator) {
	a.Describe(&f, "A symmetric data key for use outside of AWS KMS")
}

type DataKeyArgs struct {
	ValidityPeriodHours int               `pulumi:"validityPeriodHours,optional"`
	EarlyRenewalHours   int               `pulumi:"earlyRenewalHours,optional"`
	KeyId               string            `pulumi:"keyId"`
	KeySpec             types.DataKeySpec `pulumi:"keySpec"`
	NumberOfBytes       int               `pulumi:"numberOfBytes,optional"`
	WithoutPlainText    bool              `pulumi:"withoutPlainText,optional"`
}

func (f *DataKeyArgs) Annotate(a infer.Annotator) {
	a.Describe(&f.ValidityPeriodHours, "Number of hours, after initial issuing, that the key will remain valid for.")
	a.Describe(&f.EarlyRenewalHours, "Number of hours, before expiration, that the key will be renewed.")
	a.Describe(&f.KeyId, "The ID of the KMS key to use for encrypting the data key.")
	a.Describe(&f.KeySpec, "The type of data key to generate. AES_128 | AES_256. You must specify either the KeySpec or the NumberOfBytes parameter (but not both)")
	a.Deprecate(&f.NumberOfBytes, "Minimum value of 1. Maximum value of 1024.")
	a.Describe(&f.WithoutPlainText, "Whether to generate the private key without plaintext. Default is false.")
}

type DataKeyState struct {
	DataKeyArgs
	PlainText      string `pulumi:"plaintext" provider:"secret"`
	CiphertextBlob string `pulumi:"ciphertextBlob"`
	Created        int64  `pulumi:"created"`
}

func (r DataKey) Create(ctx context.Context, req infer.CreateRequest[DataKeyArgs]) (resp infer.CreateResponse[DataKeyState], err error) {
	if req.DryRun {
		return
	}
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return
	}

	svc := kms.NewFromConfig(cfg)
	input := &kms.GenerateDataKeyInput{
		KeyId:             aws.String(req.Inputs.KeyId),
		KeySpec:           req.Inputs.KeySpec,
		DryRun:            aws.Bool(req.DryRun),
		EncryptionContext: map[string]string{},
	}
	if req.Inputs.WithoutPlainText {
		rresp, err := svc.GenerateDataKeyWithoutPlaintext(ctx, &kms.GenerateDataKeyWithoutPlaintextInput{
			KeyId:             input.KeyId,
			KeySpec:           input.KeySpec,
			DryRun:            input.DryRun,
			EncryptionContext: input.EncryptionContext,
		})
		if err != nil {
			return resp, err
		}

		return infer.CreateResponse[DataKeyState]{
			ID: req.Name, Output: DataKeyState{
				CiphertextBlob: base64.StdEncoding.EncodeToString(rresp.CiphertextBlob),
				DataKeyArgs:    req.Inputs,
				Created:        time.Now().Unix(),
			},
		}, nil
	}

	rresp, err := svc.GenerateDataKey(ctx, input)
	if err != nil {
		return
	}

	return infer.CreateResponse[DataKeyState]{
		ID: req.Name, Output: DataKeyState{
			req.Inputs,
			base64.StdEncoding.EncodeToString(rresp.Plaintext),
			base64.StdEncoding.EncodeToString(rresp.CiphertextBlob),
			time.Now().Unix(),
		},
	}, nil
}

func (DataKey) Delete(ctx context.Context, req infer.DeleteRequest[DataKeyState]) (infer.DeleteResponse, error) {
	return infer.DeleteResponse{}, nil
}

func (DataKey) Update(ctx context.Context, req infer.UpdateRequest[DataKeyArgs, DataKeyState]) (infer.UpdateResponse[DataKeyState], error) {
	if req.DryRun {
		return infer.UpdateResponse[DataKeyState]{}, nil
	}
	return infer.UpdateResponse[DataKeyState]{
		Output: DataKeyState{
			req.Inputs,
			req.State.PlainText,
			req.State.CiphertextBlob,
			req.State.Created,
		},
	}, nil
}

func (DataKey) Diff(ctx context.Context, req infer.DiffRequest[DataKeyArgs, DataKeyState]) (infer.DiffResponse, error) {
	diff := map[string]p.PropertyDiff{}
	if req.Inputs.EarlyRenewalHours != req.State.EarlyRenewalHours {
		diff["earlyRenewalHours"] = p.PropertyDiff{Kind: p.Update}
	}
	if req.Inputs.ValidityPeriodHours != req.State.ValidityPeriodHours {
		diff["validityPeriodHours"] = p.PropertyDiff{Kind: p.Update}
	}

	if req.Inputs.KeySpec != req.State.KeySpec {
		diff["keySpec"] = p.PropertyDiff{Kind: p.UpdateReplace}
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

func (DataKey) WireDependencies(f infer.FieldSelector, args *DataKeyArgs, state *DataKeyState) {
	f.OutputField(&state.CiphertextBlob).DependsOn(f.InputField(&args.KeyId))
	f.OutputField(&state.CiphertextBlob).DependsOn(f.InputField(&args.KeySpec))
	f.OutputField(&state.PlainText).DependsOn(f.InputField(&args.KeyId))
	f.OutputField(&state.PlainText).DependsOn(f.InputField(&args.KeySpec))
}
