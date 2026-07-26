package aws

import (
	"context"
	"errors"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/iam"
)

// NewIAMClient creates an IAM client using static credentials.
// IAM is a global service so no region is needed, but we set us-east-1 as default.
func NewIAMClient(ctx context.Context, ak, sk, proxy string) (*iam.Client, error) {
	if ak == "" || sk == "" {
		return nil, errors.New("missing ak/sk")
	}
	hc, err := baseHTTPClient(proxy)
	if err != nil {
		return nil, err
	}

	cfg, err := config.LoadDefaultConfig(
		ctx,
		config.WithRegion("us-east-1"),
		config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(ak, sk, "")),
		config.WithHTTPClient(hc),
	)
	if err != nil {
		return nil, err
	}
	return iam.NewFromConfig(cfg), nil
}

// RotateAccessKeys creates a new access key pair, then deletes all old keys.
// Must create first because deleting the current key would invalidate the session.
// AWS allows max 2 keys per IAM user, so if already at 2 we delete the oldest first.
// Returns (newAK, newSK, error).
func RotateAccessKeys(ctx context.Context, cli *iam.Client) (string, string, error) {
	// 1. List all existing access keys
	listOut, err := cli.ListAccessKeys(ctx, &iam.ListAccessKeysInput{})
	if err != nil {
		return "", "", fmt.Errorf("ListAccessKeys failed: %w", err)
	}

	oldKeys := listOut.AccessKeyMetadata

	// 2. AWS allows max 2 keys. If already at 2, delete the oldest one first to make room.
	if len(oldKeys) >= 2 {
		// Delete the first (oldest) key to free a slot
		if oldKeys[0].AccessKeyId != nil {
			_, err := cli.DeleteAccessKey(ctx, &iam.DeleteAccessKeyInput{
				AccessKeyId: oldKeys[0].AccessKeyId,
			})
			if err != nil {
				return "", "", fmt.Errorf("DeleteAccessKey %s failed: %w", *oldKeys[0].AccessKeyId, err)
			}
		}
		oldKeys = oldKeys[1:] // remaining old keys to delete later
	}

	// 3. Create a new access key (while the current credentials are still valid)
	createOut, err := cli.CreateAccessKey(ctx, &iam.CreateAccessKeyInput{})
	if err != nil {
		return "", "", fmt.Errorf("CreateAccessKey failed: %w", err)
	}

	if createOut.AccessKey == nil || createOut.AccessKey.AccessKeyId == nil || createOut.AccessKey.SecretAccessKey == nil {
		return "", "", errors.New("CreateAccessKey returned empty result")
	}

	newAK := *createOut.AccessKey.AccessKeyId
	newSK := *createOut.AccessKey.SecretAccessKey

	// 4. Delete all remaining old keys (skip the newly created one)
	for _, meta := range oldKeys {
		if meta.AccessKeyId == nil || *meta.AccessKeyId == newAK {
			continue
		}
		_, err := cli.DeleteAccessKey(ctx, &iam.DeleteAccessKeyInput{
			AccessKeyId: meta.AccessKeyId,
		})
		if err != nil {
			// Non-fatal: new key was already created successfully
			fmt.Printf("Warning: failed to delete old key %s: %v\n", *meta.AccessKeyId, err)
		}
	}

	return newAK, newSK, nil
}
