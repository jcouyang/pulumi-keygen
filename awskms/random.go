package awskms

import (
	"context"
	"encoding/base64"

	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	p "github.com/pulumi/pulumi-go-provider"
	"github.com/pulumi/pulumi-go-provider/infer"
)

type Random struct{}

func (f *Random) Annotate(a infer.Annotator) {
	a.Describe(&f, "Cryptographically secure random byte string")
}

type RandomArgs struct {
	NumberOfBytes       int    `pulumi:"numberOfBytes"`
	ValidityPeriodHours int    `pulumi:"validityPeriodHours,optional"`
	EarlyRenewalHours   int    `pulumi:"earlyRenewalHours,optional"`
	CustomKeyStoreId    string `pulumi:"customKeyStoreId,optional"`
}

func (f *RandomArgs) Annotate(a infer.Annotator) {
	a.Describe(&f.NumberOfBytes, "Number of bytes to generate")
	a.Describe(&f.ValidityPeriodHours, "Validity period in hours, after initial creation")
	a.Describe(&f.EarlyRenewalHours, "Early renewal period in hours, before expiration")
	a.Describe(&f.CustomKeyStoreId, "Custom key store ID")
}

type RandomState struct {
	RandomArgs
	PlainText string `pulumi:"plaintext" provider:"secret"`
	Created   int64  `pulumi:"created"`
}

func (f *RandomState) Annotate(a infer.Annotator) {
	a.Describe(&f.PlainText, "Random byte string")
	a.Describe(&f.Created, "Timestamp of creation")
}

func (r Random) Create(ctx context.Context, req infer.CreateRequest[RandomArgs]) (resp infer.CreateResponse[RandomState], err error) {
	if req.DryRun {
		return
	}
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return
	}

	svc := kms.NewFromConfig(cfg)
	input := &kms.GenerateRandomInput{
		NumberOfBytes: aws.Int32(int32(req.Inputs.NumberOfBytes)),
	}
	if len(req.Inputs.CustomKeyStoreId) > 0 {
		input.CustomKeyStoreId = &req.Inputs.CustomKeyStoreId
	}
	rresp, err := svc.GenerateRandom(ctx, input)
	if err != nil {
		return
	}

	return infer.CreateResponse[RandomState]{
		ID: req.Name, Output: RandomState{
			req.Inputs,
			base64.StdEncoding.EncodeToString(rresp.Plaintext),
			time.Now().Unix(),
		},
	}, nil
}

func (Random) Delete(ctx context.Context, req infer.DeleteRequest[RandomState]) (infer.DeleteResponse, error) {
	return infer.DeleteResponse{}, nil
}

func (Random) Update(ctx context.Context, req infer.UpdateRequest[RandomArgs, RandomState]) (infer.UpdateResponse[RandomState], error) {
	if req.DryRun {
		return infer.UpdateResponse[RandomState]{}, nil
	}
	return infer.UpdateResponse[RandomState]{
		Output: RandomState{
			req.Inputs,
			req.State.PlainText,
			req.State.Created,
		},
	}, nil
}

func (Random) Diff(ctx context.Context, req infer.DiffRequest[RandomArgs, RandomState]) (infer.DiffResponse, error) {
	diff := map[string]p.PropertyDiff{}
	if req.Inputs.EarlyRenewalHours != req.State.EarlyRenewalHours {
		diff["earlyRenewalHours"] = p.PropertyDiff{Kind: p.Update}
	}
	if req.Inputs.ValidityPeriodHours != req.State.ValidityPeriodHours {
		diff["validityPeriodHours"] = p.PropertyDiff{Kind: p.Update}
	}

	if req.Inputs.NumberOfBytes != req.State.NumberOfBytes {
		diff["numberOfBytes"] = p.PropertyDiff{Kind: p.UpdateReplace}
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

func (Random) WireDependencies(f infer.FieldSelector, args *RandomArgs, state *RandomState) {
	f.OutputField(&state.PlainText).DependsOn(f.InputField(&args.CustomKeyStoreId))
	f.OutputField(&state.PlainText).DependsOn(f.InputField(&args.NumberOfBytes))
}
