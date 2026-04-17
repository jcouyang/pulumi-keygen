package pkcs11

import (
	"context"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/ThalesIgnite/crypto11"
	"github.com/jcouyang/pulumi-keygen/config"
	p "github.com/pulumi/pulumi-go-provider"
	"github.com/pulumi/pulumi-go-provider/infer"
)

type Key struct{}

func (f *Key) Annotate(a infer.Annotator) {
	a.Describe(&f, "A cryptographic key stored in a PKCS#11 HSM")
}

type KeyArgs struct {
	SlotNumber          int    `pulumi:"slotNumber,optional"`
	TokenLabel          string `pulumi:"tokenLabel,optional"`
	KeyLabel            string `pulumi:"keyLabel"`
	KeyType             string `pulumi:"keyType,optional"`
	KeySize             int    `pulumi:"keySize,optional"`
	ValidityPeriodHours int    `pulumi:"validityPeriodHours,optional"`
	EarlyRenewalHours   int    `pulumi:"earlyRenewalHours,optional"`
}

func (f *KeyArgs) Annotate(a infer.Annotator) {
	a.Describe(&f.SlotNumber, "Slot number to use for the PKCS#11 session")
	a.Describe(&f.KeyLabel, "Label for the key in the HSM")
	a.Describe(&f.KeyType, "Type of key to generate: RSA or EC (default: RSA)")
	a.Describe(&f.KeySize, "Size of the key in bits. For RSA: 2048, 3072, 4096. For EC: 256 (P-256), 384 (P-384), 521 (P-521)")
	a.Describe(&f.ValidityPeriodHours, "Number of hours, after initial issuing, that the key will remain valid for.")
	a.Describe(&f.EarlyRenewalHours, "Number of hours, before expiration, that the key will be renewed.")
}

type KeyState struct {
	KeyArgs
	PublicKey string `pulumi:"publicKey"`
	Created   int64  `pulumi:"created"`
}

func (r Key) Create(ctx context.Context, req infer.CreateRequest[KeyArgs]) (resp infer.CreateResponse[KeyState], err error) {
	if req.DryRun {
		return
	}

	// Configure crypto11 context
	c := infer.GetConfig[config.Config](ctx)
	config := &crypto11.Config{
		Path: c.HsmLocation,
		Pin:  c.HsmPin,
	}

	if len(req.Inputs.TokenLabel) > 0 {
		config.TokenLabel = req.Inputs.TokenLabel
	} else {
		config.SlotNumber = &req.Inputs.SlotNumber
	}
	ctx11, err := crypto11.Configure(config)
	if err != nil {
		return resp, fmt.Errorf("failed to configure PKCS#11: %w", err)
	}
	defer ctx11.Close()

	// Check if key already exists
	existingKey, err := ctx11.FindKeyPair(nil, []byte(req.Inputs.KeyLabel))
	if err != nil {
		return resp, fmt.Errorf("failed to search for existing key: %w", err)
	}

	var publicKey string
	var keyID string

	if existingKey != nil {
		// Key exists, use it - get public key from Signer interface
		pubKey := existingKey.Public()
		pubKeyBytes, err := x509.MarshalPKIXPublicKey(pubKey)
		if err != nil {
			return resp, fmt.Errorf("failed to marshal existing public key: %w", err)
		}
		publicKey = base64.StdEncoding.EncodeToString(pubKeyBytes)
		// Generate ID from key label for existing keys
		keyID = req.Inputs.KeyLabel
	} else {
		// Create new key
		keyType := req.Inputs.KeyType
		if keyType == "" {
			keyType = "RSA"
		}

		keySize := req.Inputs.KeySize
		if keySize == 0 {
			keySize = 2048
		}

		var newKey crypto11.Signer
		switch keyType {
		case "RSA":
			rsaKey, err := ctx11.GenerateRSAKeyPairWithLabel([]byte(req.Inputs.KeyLabel), []byte(req.Inputs.KeyLabel), keySize)
			if err != nil {
				return resp, fmt.Errorf("failed to generate RSA key: %w", err)
			}
			newKey = rsaKey
		case "EC":
			var curve elliptic.Curve
			switch keySize {
			case 256:
				curve = elliptic.P256()
			case 384:
				curve = elliptic.P384()
			case 521:
				curve = elliptic.P521()
			default:
				return resp, fmt.Errorf("unsupported EC key size: %d", keySize)
			}
			ecKey, err := ctx11.GenerateECDSAKeyPair([]byte(req.Inputs.KeyLabel), curve)
			if err != nil {
				return resp, fmt.Errorf("failed to generate EC key: %w", err)
			}
			newKey = ecKey
		default:
			return resp, fmt.Errorf("unsupported key type: %s", keyType)
		}

		// Get public key from Signer interface
		pubKey := newKey.Public()
		pubKeyBytes, err := x509.MarshalPKIXPublicKey(pubKey)
		if err != nil {
			return resp, fmt.Errorf("failed to marshal public key: %w", err)
		}
		publicKey = base64.StdEncoding.EncodeToString(pubKeyBytes)
		keyID = req.Inputs.KeyLabel
	}

	return infer.CreateResponse[KeyState]{
		ID: keyID,
		Output: KeyState{
			KeyArgs:   req.Inputs,
			PublicKey: publicKey,
			Created:   time.Now().Unix(),
		},
	}, nil
}

func (Key) Delete(ctx context.Context, req infer.DeleteRequest[KeyState]) (infer.DeleteResponse, error) {
	// Configure crypto11 context to delete the key
	c := infer.GetConfig[config.Config](ctx)
	config := &crypto11.Config{
		Path: c.HsmLocation,
		Pin:  c.HsmPin,
	}

	if len(req.State.TokenLabel) > 0 {
		config.TokenLabel = req.State.TokenLabel
	} else {
		config.SlotNumber = &req.State.SlotNumber
	}
	ctx11, err := crypto11.Configure(config)
	if err != nil {
		return infer.DeleteResponse{}, fmt.Errorf("failed to configure PKCS#11 for deletion: %w", err)
	}
	defer ctx11.Close()

	// Find and delete the key
	key, err := ctx11.FindKeyPair(nil, []byte(req.State.KeyLabel))
	if err != nil {
		return infer.DeleteResponse{}, fmt.Errorf("failed to find key for deletion: %w", err)
	}

	if key != nil {
		err = key.Delete()
		if err != nil {
			return infer.DeleteResponse{}, fmt.Errorf("failed to delete key: %w", err)
		}
	}

	return infer.DeleteResponse{}, nil
}

func (Key) Update(ctx context.Context, req infer.UpdateRequest[KeyArgs, KeyState]) (infer.UpdateResponse[KeyState], error) {
	if req.DryRun {
		return infer.UpdateResponse[KeyState]{}, nil
	}
	return infer.UpdateResponse[KeyState]{
		Output: KeyState{
			KeyArgs:   req.Inputs,
			PublicKey: req.State.PublicKey,
			Created:   req.State.Created,
		},
	}, nil
}

func (Key) Diff(ctx context.Context, req infer.DiffRequest[KeyArgs, KeyState]) (infer.DiffResponse, error) {
	diff := map[string]p.PropertyDiff{}
	if req.Inputs.EarlyRenewalHours != req.State.EarlyRenewalHours {
		diff["earlyRenewalHours"] = p.PropertyDiff{Kind: p.Update}
	}
	if req.Inputs.ValidityPeriodHours != req.State.ValidityPeriodHours {
		diff["validityPeriodHours"] = p.PropertyDiff{Kind: p.Update}
	}
	if req.Inputs.SlotNumber != req.State.SlotNumber {
		diff["slotNumber"] = p.PropertyDiff{Kind: p.UpdateReplace}
	}
	if req.Inputs.KeyLabel != req.State.KeyLabel {
		diff["keyLabel"] = p.PropertyDiff{Kind: p.UpdateReplace}
	}
	if req.Inputs.KeyType != req.State.KeyType {
		diff["keyType"] = p.PropertyDiff{Kind: p.UpdateReplace}
	}
	if req.Inputs.KeySize != req.State.KeySize {
		diff["keySize"] = p.PropertyDiff{Kind: p.UpdateReplace}
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

func (Key) WireDependencies(f infer.FieldSelector, args *KeyArgs, state *KeyState) {
	f.OutputField(&state.PublicKey).DependsOn(f.InputField(&args.KeyLabel))
	f.OutputField(&state.PublicKey).DependsOn(f.InputField(&args.KeyType))
	f.OutputField(&state.PublicKey).DependsOn(f.InputField(&args.KeySize))
}
