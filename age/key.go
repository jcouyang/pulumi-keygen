package age

import (
	"context"
	"encoding/base64"
	"fmt"
	"time"

	"filippo.io/age"
	"github.com/jcouyang/pulumi-keygen/internal/bech32"
	p "github.com/pulumi/pulumi-go-provider"
	"github.com/pulumi/pulumi-go-provider/infer"
	"golang.org/x/crypto/curve25519"
)

type Identity struct{}

func (f *Identity) Annotate(a infer.Annotator) {
	a.Describe(&f, "Age Encryption Identity, standard age private key")
}

type IdentityArgs struct {
	ValidityPeriodHours int    `pulumi:"validityPeriodHours,optional"`
	EarlyRenewalHours   int    `pulumi:"earlyRenewalHours,optional"`
	Random              string `pulumi:"random,optional" provider:"secret"`
}

func (f *IdentityArgs) Annotate(a infer.Annotator) {
	a.Describe(&f.ValidityPeriodHours, "Number of hours, after initial issuing, that the key will remain valid for.")
	a.Describe(&f.EarlyRenewalHours, "Number of hours, before expiration, that the key will be renewed.")
	a.Describe(&f.Random, "Custom random bytes, it must be 32 bytes, base64 encoded, optional, if not provided go rand is used to generate the random bytes")
}

type IdentityState struct {
	IdentityArgs
	PrivateKey string `pulumi:"key" provider:"secret"`
	Recipient  string `pulumi:"recipient"`
	Created    int64  `pulumi:"created"`
}

func (Identity) Create(ctx context.Context, req infer.CreateRequest[IdentityArgs]) (resp infer.CreateResponse[IdentityState], err error) {
	if req.DryRun {
		return
	}
	var identity *age.X25519Identity

	if len(req.Inputs.Random) > 0 {
		decoded, err := base64.StdEncoding.DecodeString(req.Inputs.Random)
		if err != nil {
			return resp, fmt.Errorf("provided random is not base64 encoded")
		}
		if size := len(decoded); size > 0 && size != curve25519.ScalarSize {
			return resp, fmt.Errorf("provided random has incorrect(%d) size", size)
		}
		encoded, err := bech32.Encode("AGE-SECRET-KEY-", decoded)
		if err != nil {
			return resp, fmt.Errorf("failed to encode random to bech32")
		}
		identity, err = age.ParseX25519Identity(encoded)
	} else {
		identity, err = age.GenerateX25519Identity()
	}
	if err != nil {
		return infer.CreateResponse[IdentityState]{}, fmt.Errorf("failed to generate x25519 identity: %s", err)
	}
	recipient := identity.Recipient().String()
	if err != nil {
		return resp, err
	}
	return infer.CreateResponse[IdentityState]{
		ID: recipient,
		Output: IdentityState{
			req.Inputs,
			identity.String(),
			recipient,
			time.Now().Unix(),
		},
	}, nil
}

func (Identity) Delete(ctx context.Context, req infer.DeleteRequest[IdentityState]) (infer.DeleteResponse, error) {
	return infer.DeleteResponse{}, nil
}

func (Identity) Update(ctx context.Context, req infer.UpdateRequest[IdentityArgs, IdentityState]) (infer.UpdateResponse[IdentityState], error) {
	if req.DryRun {
		return infer.UpdateResponse[IdentityState]{}, nil
	}
	return infer.UpdateResponse[IdentityState]{
		Output: IdentityState{
			req.Inputs,
			req.State.PrivateKey,
			req.State.Recipient,
			req.State.Created,
		},
	}, nil
}

func (Identity) Diff(ctx context.Context, req infer.DiffRequest[IdentityArgs, IdentityState]) (infer.DiffResponse, error) {
	diff := map[string]p.PropertyDiff{}
	if req.Inputs.EarlyRenewalHours != req.State.EarlyRenewalHours {
		diff["earlyRenewalHours"] = p.PropertyDiff{Kind: p.Update}
	}
	if req.Inputs.ValidityPeriodHours != req.State.ValidityPeriodHours {
		diff["validityPeriodHours"] = p.PropertyDiff{Kind: p.Update}
	}
	if req.Inputs.Random != req.State.Random {
		diff["random"] = p.PropertyDiff{Kind: p.UpdateReplace}
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

func (Identity) WireDependencies(f infer.FieldSelector, args *IdentityArgs, state *IdentityState) {
	f.OutputField(&state.PrivateKey).DependsOn(f.InputField(&args.Random))
}
