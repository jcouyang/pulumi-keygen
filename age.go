package main

import (
	"context"
	"time"

	"filippo.io/age"
	"github.com/pulumi/pulumi-go-provider/infer"
	p "github.com/pulumi/pulumi-go-provider"
)

type Age struct{}

func (f *Age) Annotate(a infer.Annotator) {
	a.Describe(&f, "Age encryption")
}

type AgeArgs struct {
	ValidityPeriodHours int `pulumi:"validityPeriodHours"`
	EarlyRenewalHours int `pulumi:"earlyRenewalHours"`
	SshPrivateKeyPem string `pulumi:"sshPrivateKeyPem,optional" provider:"secret"`
}

func (f *AgeArgs) Annotate(a infer.Annotator) {
	a.Describe(&f.SshPrivateKeyPem, "Optional, if provide will parse the key otherwise will generate an Ed25519 key")
}

type AgeState struct {
	AgeArgs
	PrivateKey string `pulumi:"key" provider:"secret"`
	Recipient string `pulumi:"recipient"`
	Created int64 `pulumi:"created"`
}

func (f *AgeState) Annotate(a infer.Annotator) {
	// a.Describe(&f.ValidityPeriodHours, " how long this key valid for")
	// a.Describe(&f.EarlyRenewalHours, "")
}

func (Age) Create(ctx context.Context, req infer.CreateRequest[AgeArgs]) (resp infer.CreateResponse[AgeState], err error) {
	if req.DryRun {
		return infer.CreateResponse[AgeState]{}, nil
	}
	identity, err := age.GenerateX25519Identity()
	if err != nil {return resp, err}
	return infer.CreateResponse[AgeState]{
		ID: req.Name,
		Output: AgeState{
			req.Inputs,
			identity.String(),
			identity.Recipient().String(),
			time.Now().Unix(),
		},
	}, nil
}

func (Age) Delete(ctx context.Context, req infer.DeleteRequest[AgeState]) (infer.DeleteResponse, error) {
	return infer.DeleteResponse{}, nil
}

// func (File) Check(ctx context.Context, req infer.CheckRequest) (infer.CheckResponse[FileArgs], error) {
// 	if _, ok := req.NewInputs.GetOk("path"); !ok {
// 		req.NewInputs = req.NewInputs.Set("path", property.New(req.Name))
// 	}
// 	args, f, err := infer.DefaultCheck[FileArgs](ctx, req.NewInputs)

// 	return infer.CheckResponse[FileArgs]{
// 		Inputs:   args,
// 		Failures: f,
// 	}, err
// }

func (Age) Update(ctx context.Context, req infer.UpdateRequest[AgeArgs, AgeState]) (infer.UpdateResponse[AgeState], error) {
	// if req.DryRun { // Don't do the update if in preview
		return infer.UpdateResponse[AgeState]{}, nil
	// }
	
	// identity, err := age.GenerateX25519Identity()
	// if err != nil {return infer.UpdateResponse[AgeState]{}, err}
	// return infer.UpdateResponse[AgeState]{
		// Output: AgeState{
			// req.Inputs,
			// identity.String(),
			// identity.Recipient().String(),
			// time.Now().Unix(),
		// },
	// }, nil
}

func (Age) Diff(ctx context.Context, req infer.DiffRequest[AgeArgs, AgeState]) (infer.DiffResponse, error) {
	diff := map[string]p.PropertyDiff{}
	if req.Inputs.EarlyRenewalHours != req.State.EarlyRenewalHours {
		diff["earlyRenewalHours"] = p.PropertyDiff{Kind: p.Update}
	}
	if req.Inputs.ValidityPeriodHours != req.State.ValidityPeriodHours {
		diff["validityPeriodHours"] = p.PropertyDiff{Kind: p.Update}
	}
	if req.Inputs.SshPrivateKeyPem != req.State.SshPrivateKeyPem {
		diff["sshPrivateKeyPem"] = p.PropertyDiff{Kind: p.UpdateReplace}
	}
	if req.Inputs.ValidityPeriodHours != 0 &&
		time.Now().Unix() >=
			req.State.Created + int64(req.Inputs.ValidityPeriodHours)*60 - int64(req.Inputs.EarlyRenewalHours)*60 {
		diff["expired"] = p.PropertyDiff{Kind: p.UpdateReplace}
	}
	return infer.DiffResponse{
		DeleteBeforeReplace: true,
		HasChanges: len(diff) > 0,
		DetailedDiff: diff,
	}, nil
}

// func (File) Read(ctx context.Context, req infer.ReadRequest[FileArgs, FileState]) (infer.ReadResponse[FileArgs, FileState], error) {
// 	path := req.ID
// 	byteContent, err := os.ReadFile(path)
// 	if err != nil {
// 		return infer.ReadResponse[FileArgs, FileState]{}, err
// 	}
// 	content := string(byteContent)
// 	return infer.ReadResponse[FileArgs, FileState]{
// 		ID: path,
// 		Inputs: FileArgs{
// 			Path:    path,
// 			Force:   req.State.Force,
// 			Content: content,
// 		},
// 		State: FileState{
// 			Path:    path,
// 			Force:   req.State.Force,
// 			Content: content,
// 		},
// 	}, nil
// }

// func (File) WireDependencies(f infer.FieldSelector, args *FileArgs, state *FileState) {
// 	f.OutputField(&state.Content).DependsOn(f.InputField(&args.Content))
// 	f.OutputField(&state.Force).DependsOn(f.InputField(&args.Force))
// 	f.OutputField(&state.Path).DependsOn(f.InputField(&args.Path))
// }
