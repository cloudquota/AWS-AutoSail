package aws

import (
	"context"
	"encoding/base64"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/lightsail"
	lightsailtypes "github.com/aws/aws-sdk-go-v2/service/lightsail/types"
)

func ListEC2InstancesStable(ctx context.Context, cli *ec2.Client) ([]EC2InstanceView, error) {
	paginator := ec2.NewDescribeInstancesPaginator(cli, &ec2.DescribeInstancesInput{})
	var list []EC2InstanceView

	for paginator.HasMorePages() {
		out, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("list EC2 instances failed: %v", err)
		}

		for _, reservation := range out.Reservations {
			for _, ins := range reservation.Instances {
				if ins.State != nil && ins.State.Name == ec2types.InstanceStateNameTerminated {
					continue
				}

				name := ""
				for _, tag := range ins.Tags {
					if aws.ToString(tag.Key) == "Name" {
						name = aws.ToString(tag.Value)
						break
					}
				}

				publicIPv6 := ""
				for _, nic := range ins.NetworkInterfaces {
					for _, ipv6 := range nic.Ipv6Addresses {
						publicIPv6 = aws.ToString(ipv6.Ipv6Address)
						if publicIPv6 != "" {
							break
						}
					}
					if publicIPv6 != "" {
						break
					}
				}

				launchedAt := ""
				if ins.LaunchTime != nil {
					launchedAt = ins.LaunchTime.Local().Format("2006-01-02 15:04:05")
				}

				state := ""
				if ins.State != nil {
					state = string(ins.State.Name)
				}

				list = append(list, EC2InstanceView{
					ID:           aws.ToString(ins.InstanceId),
					Name:         name,
					State:        state,
					InstanceType: string(ins.InstanceType),
					PublicIPv4:   aws.ToString(ins.PublicIpAddress),
					PublicIPv6:   publicIPv6,
					PrivateIPv4:  aws.ToString(ins.PrivateIpAddress),
					Zone:         aws.ToString(ins.Placement.AvailabilityZone),
					LaunchedAt:   launchedAt,
				})
			}
		}
	}

	sort.Slice(list, func(i, j int) bool {
		if list[i].Zone != list[j].Zone {
			return list[i].Zone < list[j].Zone
		}
		if list[i].Name != list[j].Name {
			return list[i].Name < list[j].Name
		}
		return list[i].ID < list[j].ID
	})

	return list, nil
}

func CreateEC2InstanceStable(ctx context.Context, cli *ec2.Client, in CreateEC2InstanceInput) error {
	in.AMI = strings.TrimSpace(in.AMI)
	if in.AMI == "" {
		return fmt.Errorf("AMI is required")
	}
	if in.Count <= 0 {
		in.Count = 1
	}

	in.InstanceType = strings.TrimSpace(in.InstanceType)
	if in.InstanceType == "" {
		in.InstanceType = "t3.micro"
	}

	in.Name = strings.TrimSpace(in.Name)
	if in.Name == "" {
		in.Name = fmt.Sprintf("ec2-%d", time.Now().Unix())
	}

	runIn := &ec2.RunInstancesInput{
		ImageId:      aws.String(in.AMI),
		InstanceType: ec2types.InstanceType(in.InstanceType),
		MinCount:     aws.Int32(in.Count),
		MaxCount:     aws.Int32(in.Count),
		MetadataOptions: &ec2types.InstanceMetadataOptionsRequest{
			HttpTokens:   ec2types.HttpTokensStateRequired,
			HttpEndpoint: ec2types.InstanceMetadataEndpointStateEnabled,
		},
		TagSpecifications: []ec2types.TagSpecification{
			{
				ResourceType: ec2types.ResourceTypeInstance,
				Tags: []ec2types.Tag{
					{Key: aws.String("Name"), Value: aws.String(in.Name)},
				},
			},
		},
	}

	if strings.TrimSpace(in.UserData) != "" {
		runIn.UserData = aws.String(base64.StdEncoding.EncodeToString([]byte(in.UserData)))
	}

	if in.EnableIPv6 {
		subnetID, err := selectIPv6SubnetStable(ctx, cli)
		if err != nil {
			return err
		}
		if err := ensureSubnetIPv6Route(ctx, cli, subnetID); err != nil {
			return err
		}
		runIn.SubnetId = aws.String(subnetID)
		runIn.Ipv6AddressCount = aws.Int32(1)
	} else {
		subnetID, err := selectDefaultLaunchSubnetStable(ctx, cli)
		if err != nil {
			return err
		}
		runIn.SubnetId = aws.String(subnetID)
	}

	out, err := cli.RunInstances(ctx, runIn)
	if err != nil {
		return fmt.Errorf("create EC2 instance failed: %v", err)
	}

	if in.Count > 1 && len(out.Instances) > 1 {
		if err := tagCreatedEC2Instances(ctx, cli, out.Instances, in.Name); err != nil {
			return fmt.Errorf("instances were created, but tagging names failed: %v", err)
		}
	}

	return nil
}

func selectDefaultLaunchSubnetStable(ctx context.Context, cli *ec2.Client) (string, error) {
	vpcOut, err := cli.DescribeVpcs(ctx, &ec2.DescribeVpcsInput{
		Filters: []ec2types.Filter{{Name: aws.String("is-default"), Values: []string{"true"}}},
	})
	if err != nil {
		return "", fmt.Errorf("describe default VPC failed: %v", err)
	}
	if len(vpcOut.Vpcs) == 0 {
		return "", fmt.Errorf("no default VPC is available in this region")
	}

	vpcID := aws.ToString(vpcOut.Vpcs[0].VpcId)
	subnetOut, err := cli.DescribeSubnets(ctx, &ec2.DescribeSubnetsInput{
		Filters: []ec2types.Filter{{Name: aws.String("vpc-id"), Values: []string{vpcID}}},
	})
	if err != nil {
		return "", fmt.Errorf("describe default VPC subnets failed: %v", err)
	}
	if len(subnetOut.Subnets) == 0 {
		return "", fmt.Errorf("no usable subnet was found in the default VPC")
	}

	type subnetInfo struct {
		ID           string
		Zone         string
		DefaultForAZ bool
	}

	candidates := make([]subnetInfo, 0, len(subnetOut.Subnets))
	for _, subnet := range subnetOut.Subnets {
		candidates = append(candidates, subnetInfo{
			ID:           aws.ToString(subnet.SubnetId),
			Zone:         aws.ToString(subnet.AvailabilityZone),
			DefaultForAZ: aws.ToBool(subnet.DefaultForAz),
		})
	}

	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].DefaultForAZ != candidates[j].DefaultForAZ {
			return candidates[i].DefaultForAZ
		}
		if candidates[i].Zone != candidates[j].Zone {
			return candidates[i].Zone < candidates[j].Zone
		}
		return candidates[i].ID < candidates[j].ID
	})

	return candidates[0].ID, nil
}

func selectIPv6SubnetStable(ctx context.Context, cli *ec2.Client) (string, error) {
	vpcOut, err := cli.DescribeVpcs(ctx, &ec2.DescribeVpcsInput{
		Filters: []ec2types.Filter{{Name: aws.String("is-default"), Values: []string{"true"}}},
	})
	if err != nil {
		return "", fmt.Errorf("describe default VPC failed: %v", err)
	}
	if len(vpcOut.Vpcs) == 0 {
		return "", fmt.Errorf("no default VPC is available in this region for IPv6 launch")
	}

	vpcID := aws.ToString(vpcOut.Vpcs[0].VpcId)
	subnetOut, err := cli.DescribeSubnets(ctx, &ec2.DescribeSubnetsInput{
		Filters: []ec2types.Filter{{Name: aws.String("vpc-id"), Values: []string{vpcID}}},
	})
	if err != nil {
		return "", fmt.Errorf("describe default VPC subnets failed: %v", err)
	}
	if len(subnetOut.Subnets) == 0 {
		return "", fmt.Errorf("no usable subnet was found in the default VPC")
	}

	subnetID, hasIPv6 := pickSubnetWithIPv6(subnetOut.Subnets)
	if hasIPv6 {
		return subnetID, nil
	}

	return ensureDefaultIPv6SubnetStable(ctx, cli, vpcID, subnetOut.Subnets)
}

func ensureDefaultIPv6SubnetStable(ctx context.Context, cli *ec2.Client, vpcID string, subnets []ec2types.Subnet) (string, error) {
	if strings.TrimSpace(vpcID) == "" {
		return "", fmt.Errorf("default VPC is missing")
	}
	if len(subnets) == 0 {
		return "", fmt.Errorf("no usable subnet was found in the default VPC")
	}

	vpcIPv6, err := ensureVpcIPv6(ctx, cli, vpcID)
	if err != nil {
		return "", err
	}

	subnetID, hasIPv6 := pickSubnetWithIPv6(subnets)
	if hasIPv6 {
		return subnetID, nil
	}

	return enableSubnetIPv6(ctx, cli, subnets, vpcIPv6)
}

func ListInstancesStable(ctx context.Context, cli LightsailAPI) ([]InstanceView, error) {
	out, err := cli.GetInstances(ctx, &lightsail.GetInstancesInput{})
	if err != nil {
		return nil, fmt.Errorf("list Lightsail instances failed: %v", err)
	}
	if out == nil {
		return nil, nil
	}

	sipOut, _ := cli.GetStaticIps(ctx, &lightsail.GetStaticIpsInput{})
	staticMap := map[string]string{}
	if sipOut != nil {
		for _, si := range sipOut.StaticIps {
			if si.AttachedTo != nil && si.IpAddress != nil {
				if si.IsAttached == nil || *si.IsAttached {
					staticMap[*si.AttachedTo] = *si.IpAddress
				}
			}
		}
	}

	var list []InstanceView
	for _, ins := range out.Instances {
		state := ""
		if ins.State != nil && ins.State.Name != nil {
			state = *ins.State.Name
		}

		publicIPv6 := ""
		if len(ins.Ipv6Addresses) > 0 {
			publicIPv6 = ins.Ipv6Addresses[0]
		}

		created := ""
		if ins.CreatedAt != nil {
			created = ins.CreatedAt.Format("2006-01-02 15:04:05")
		}

		name := str(ins.Name)
		list = append(list, InstanceView{
			Name:       name,
			State:      state,
			PublicIPv4: str(ins.PublicIpAddress),
			PublicIPv6: publicIPv6,
			StaticIPv4: staticMap[name],
			Zone:       str(ins.Location.AvailabilityZone),
			BundleID:   str(ins.BundleId),
			Created:    created,
		})
	}

	sort.Slice(list, func(i, j int) bool {
		if list[i].Zone != list[j].Zone {
			return list[i].Zone < list[j].Zone
		}
		if list[i].Name != list[j].Name {
			return list[i].Name < list[j].Name
		}
		return list[i].Created > list[j].Created
	})

	return list, nil
}

func CreateInstanceStable(ctx context.Context, cli LightsailAPI, in CreateInstanceInput) error {
	in.InstanceName = strings.TrimSpace(in.InstanceName)
	in.AvailabilityZone = strings.TrimSpace(in.AvailabilityZone)
	in.BlueprintID = strings.TrimSpace(in.BlueprintID)
	in.BundleID = strings.TrimSpace(in.BundleID)

	if in.InstanceName == "" {
		return fmt.Errorf("instance name is required")
	}
	if in.AvailabilityZone == "" {
		return fmt.Errorf("availability zone is required")
	}
	if in.BlueprintID == "" {
		return fmt.Errorf("blueprint is required")
	}
	if in.BundleID == "" {
		return fmt.Errorf("bundle is required")
	}

	req := &lightsail.CreateInstancesInput{
		InstanceNames:    []string{in.InstanceName},
		AvailabilityZone: &in.AvailabilityZone,
		BlueprintId:      &in.BlueprintID,
		BundleId:         &in.BundleID,
		IpAddressType:    lightsailtypes.IpAddressType(normalizeLightsailIPAddressType(in.IPAddressType)),
	}
	if strings.TrimSpace(in.UserData) != "" {
		req.UserData = &in.UserData
	}

	_, err := cli.CreateInstances(ctx, req)
	if err != nil {
		return fmt.Errorf("create Lightsail instance failed: %v", err)
	}

	if in.EnableFWAll {
		if err := OpenAllPorts(ctx, cli, in.InstanceName); err != nil {
			return fmt.Errorf("instance was created, but opening all ports failed: %v", err)
		}
	}

	return nil
}

func DeleteInstanceWithStaticIPCleanupStable(ctx context.Context, cli LightsailAPI, name string) error {
	if _, err := DeletePreviousStaticIPOnlyForInstance(ctx, cli, name); err != nil {
		return fmt.Errorf("cleanup attached static IP before delete failed: %v", err)
	}

	return SafeRetry("delete instance", 8, 1200*time.Millisecond, func() error {
		_, err := cli.DeleteInstance(ctx, &lightsail.DeleteInstanceInput{InstanceName: &name})
		return err
	})
}

func SwapStaticIPForInstanceStable(ctx context.Context, cli LightsailAPI, instanceName string) error {
	insOut, err := cli.GetInstances(ctx, &lightsail.GetInstancesInput{})
	if err == nil && insOut != nil {
		for _, ins := range insOut.Instances {
			if str(ins.Name) == instanceName {
				if str(ins.PublicIpAddress) == "" {
					return fmt.Errorf("instance has no public IPv4, so static IPv4 cannot be swapped")
				}
				break
			}
		}
	}

	if _, err := DeletePreviousStaticIPOnlyForInstance(ctx, cli, instanceName); err != nil {
		return fmt.Errorf("cleanup previous static IP failed: %v", err)
	}

	newName := fmt.Sprintf("sip-%s-%d", sanitize(instanceName), time.Now().Unix())
	if err := SafeRetry("allocate static ip", 8, 1200*time.Millisecond, func() error {
		_, err := cli.AllocateStaticIp(ctx, &lightsail.AllocateStaticIpInput{StaticIpName: &newName})
		return err
	}); err != nil {
		return err
	}

	if err := SafeRetry("attach static ip", 8, 1200*time.Millisecond, func() error {
		_, err := cli.AttachStaticIp(ctx, &lightsail.AttachStaticIpInput{
			StaticIpName: &newName,
			InstanceName: &instanceName,
		})
		return err
	}); err != nil {
		_ = DeleteStaticIP(ctx, cli, newName)
		return err
	}

	return nil
}

func normalizeLightsailIPAddressType(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "ipv4", "ipv6", "dualstack":
		return strings.ToLower(strings.TrimSpace(v))
	default:
		return "dualstack"
	}
}
