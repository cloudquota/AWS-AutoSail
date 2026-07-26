package aws

import (
	"context"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/account"
)

const accountServiceRegion = "us-east-1"

type AccountRegionStatus struct {
	RegionName    string `json:"region_name"`
	RegionOptStatus string `json:"region_opt_status"`
}

func NewAccountClient(ctx context.Context, ak, sk, proxy string) (*account.Client, error) {
	if strings.TrimSpace(ak) == "" || strings.TrimSpace(sk) == "" {
		return nil, fmt.Errorf("missing ak/sk")
	}

	hc, err := baseHTTPClient(proxy)
	if err != nil {
		return nil, err
	}

	cfg, err := config.LoadDefaultConfig(
		ctx,
		config.WithRegion(accountServiceRegion),
		config.WithCredentialsProvider(aws.NewCredentialsCache(credentials.NewStaticCredentialsProvider(ak, sk, ""))),
		config.WithHTTPClient(hc),
	)
	if err != nil {
		return nil, err
	}

	return account.NewFromConfig(cfg), nil
}

func ListAccountRegions(ctx context.Context, cli *account.Client) ([]AccountRegionStatus, error) {
	var (
		results []AccountRegionStatus
		token   *string
	)

	for {
		out, err := cli.ListRegions(ctx, &account.ListRegionsInput{
			MaxResults: aws.Int32(50),
			NextToken:  token,
		})
		if err != nil {
			return nil, fmt.Errorf("list regions failed: %v", err)
		}

		for _, region := range out.Regions {
			results = append(results, AccountRegionStatus{
				RegionName:      aws.ToString(region.RegionName),
				RegionOptStatus: string(region.RegionOptStatus),
			})
		}

		if out.NextToken == nil || aws.ToString(out.NextToken) == "" {
			break
		}
		token = out.NextToken
	}

	return results, nil
}

func EnableAccountRegion(ctx context.Context, cli *account.Client, regionName string) error {
	regionName = strings.TrimSpace(regionName)
	if regionName == "" {
		return fmt.Errorf("missing region name")
	}

	_, err := cli.EnableRegion(ctx, &account.EnableRegionInput{
		RegionName: aws.String(regionName),
	})
	if err != nil {
		return fmt.Errorf("enable region failed: %v", err)
	}

	return nil
}
