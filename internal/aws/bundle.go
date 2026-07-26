package aws

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/aws/aws-sdk-go-v2/service/lightsail"
)

type BundleView struct {
	ID                 string
	Name               string
	InstanceType       string
	CPUCount           int32
	RAMSizeGB          float32
	DiskSizeGB         int32
	TransferPerMonthGB int32
}

func ListBundles(ctx context.Context, cli LightsailAPI) ([]BundleView, error) {
	var (
		list      []BundleView
		pageToken *string
	)

	for {
		out, err := cli.GetBundles(ctx, &lightsail.GetBundlesInput{PageToken: pageToken})
		if err != nil {
			return nil, fmt.Errorf("list Lightsail bundles failed: %v", err)
		}
		if out == nil {
			break
		}

		for _, bundle := range out.Bundles {
			id := str(bundle.BundleId)
			if id == "" || (bundle.IsActive != nil && !*bundle.IsActive) {
				continue
			}
			if len(bundle.SupportedPlatforms) > 0 {
				linux := false
				for _, platform := range bundle.SupportedPlatforms {
					if strings.EqualFold(string(platform), "LINUX_UNIX") {
						linux = true
						break
					}
				}
				if !linux {
					continue
				}
			}

			list = append(list, BundleView{
				ID:                 id,
				Name:               str(bundle.Name),
				InstanceType:       str(bundle.InstanceType),
				CPUCount:           int32Value(bundle.CpuCount),
				RAMSizeGB:          float32Value(bundle.RamSizeInGb),
				DiskSizeGB:         int32Value(bundle.DiskSizeInGb),
				TransferPerMonthGB: int32Value(bundle.TransferPerMonthInGb),
			})
		}

		if out.NextPageToken == nil || str(out.NextPageToken) == "" {
			break
		}
		pageToken = out.NextPageToken
	}

	sort.SliceStable(list, func(i, j int) bool {
		if list[i].CPUCount != list[j].CPUCount {
			return list[i].CPUCount < list[j].CPUCount
		}
		if list[i].RAMSizeGB != list[j].RAMSizeGB {
			return list[i].RAMSizeGB < list[j].RAMSizeGB
		}
		if list[i].DiskSizeGB != list[j].DiskSizeGB {
			return list[i].DiskSizeGB < list[j].DiskSizeGB
		}
		return list[i].ID < list[j].ID
	})

	return list, nil
}
