package aws

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/smithy-go"
)

type EC2InstanceView struct {
	ID           string
	Name         string
	State        string
	InstanceType string
	PublicIPv4   string
	PublicIPv6   string
	PrivateIPv4  string
	Zone         string
	LaunchedAt   string
}

type EC2AMIOption struct {
	Key     string
	Name    string
	Owner   string
	Pattern string
	Arch    string
}

var defaultEC2AMIOptions = []EC2AMIOption{
	{Key: "ubuntu-24.04", Name: "Ubuntu 24.04 LTS", Owner: "099720109477", Pattern: "ubuntu/images/hvm-ssd-gp3/ubuntu-noble-24.04-*", Arch: "x86_64"},
	{Key: "ubuntu-22.04", Name: "Ubuntu 22.04 LTS", Owner: "099720109477", Pattern: "ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-*", Arch: "x86_64"},
	{Key: "debian-12", Name: "Debian 12", Owner: "136693071363", Pattern: "debian-12-*", Arch: "x86_64"},
	{Key: "amzn-2023", Name: "Amazon Linux 2023", Owner: "137112412989", Pattern: "al2023-ami-2023.*", Arch: "x86_64"},
}

type CreateEC2InstanceInput struct {
	Name         string
	AMI          string
	InstanceType string
	Count        int32
	UserData     string
	EnableIPv6   bool
}

func ResolveEC2AMI(ctx context.Context, cli *ec2.Client, key string) (string, error) {
	key = strings.TrimSpace(key)
	if key == "" {
		key = "ubuntu-24.04"
	}

	for _, opt := range defaultEC2AMIOptions {
		if opt.Key != key {
			continue
		}
		amiID, err := latestAMI(ctx, cli, opt.Owner, opt.Pattern, opt.Arch)
		if err != nil {
			return "", err
		}
		if amiID == "" {
			return "", fmt.Errorf("未找到匹配的 AMI: %s", opt.Name)
		}
		return amiID, nil
	}

	if strings.HasPrefix(key, "ami-") {
		return key, nil
	}

	return "", fmt.Errorf("未知 AMI 选项: %s", key)
}

func latestAMI(ctx context.Context, cli *ec2.Client, owner, pattern, arch string) (string, error) {
	out, err := cli.DescribeImages(ctx, &ec2.DescribeImagesInput{
		Owners: []string{owner},
		Filters: []ec2types.Filter{
			{Name: aws.String("name"), Values: []string{pattern}},
			{Name: aws.String("architecture"), Values: []string{arch}},
			{Name: aws.String("virtualization-type"), Values: []string{"hvm"}},
		},
	})
	if err != nil {
		return "", err
	}
	if len(out.Images) == 0 {
		return "", nil
	}

	sort.Slice(out.Images, func(i, j int) bool {
		return aws.ToString(out.Images[i].CreationDate) > aws.ToString(out.Images[j].CreationDate)
	})

	return aws.ToString(out.Images[0].ImageId), nil
}

func ListEC2Instances(ctx context.Context, cli *ec2.Client) ([]EC2InstanceView, error) {
	out, err := cli.DescribeInstances(ctx, &ec2.DescribeInstancesInput{})
	if err != nil {
		return nil, fmt.Errorf("拉取 EC2 实例失败: %v", err)
	}

	var list []EC2InstanceView
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

	sort.Slice(list, func(i, j int) bool {
		if list[i].Zone != list[j].Zone {
			return list[i].Zone < list[j].Zone
		}
		return list[i].ID < list[j].ID
	})

	return list, nil
}

func CreateEC2Instance(ctx context.Context, cli *ec2.Client, in CreateEC2InstanceInput) error {
	if in.Count <= 0 {
		in.Count = 1
	}
	if strings.TrimSpace(in.InstanceType) == "" {
		in.InstanceType = "t3.micro"
	}
	if strings.TrimSpace(in.Name) == "" {
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
		subnetID, err := selectIPv6Subnet(ctx, cli)
		if err != nil {
			return err
		}
		if err := ensureSubnetIPv6Route(ctx, cli, subnetID); err != nil {
			return err
		}
		runIn.SubnetId = aws.String(subnetID)
		runIn.Ipv6AddressCount = aws.Int32(1)
	} else {
		subnetID, err := selectDefaultLaunchSubnet(ctx, cli)
		if err != nil {
			return err
		}
		if subnetID != "" {
			runIn.SubnetId = aws.String(subnetID)
		}
	}

	out, err := cli.RunInstances(ctx, runIn)
	if err != nil {
		return fmt.Errorf("创建 EC2 实例失败: %v", err)
	}

	if in.Count > 1 && len(out.Instances) > 1 {
		if err := tagCreatedEC2Instances(ctx, cli, out.Instances, in.Name); err != nil {
			return fmt.Errorf("实例已创建，但设置实例名称失败: %v", err)
		}
	}
	return nil
}

func StartEC2Instance(ctx context.Context, cli *ec2.Client, id string) error {
	_, err := cli.StartInstances(ctx, &ec2.StartInstancesInput{InstanceIds: []string{id}})
	if err != nil {
		return fmt.Errorf("启动失败: %v", err)
	}
	return nil
}

func StopEC2Instance(ctx context.Context, cli *ec2.Client, id string) error {
	_, err := cli.StopInstances(ctx, &ec2.StopInstancesInput{InstanceIds: []string{id}})
	if err != nil {
		return fmt.Errorf("停止失败: %v", err)
	}
	return nil
}

func RebootEC2Instance(ctx context.Context, cli *ec2.Client, id string) error {
	_, err := cli.RebootInstances(ctx, &ec2.RebootInstancesInput{InstanceIds: []string{id}})
	if err != nil {
		return fmt.Errorf("重启失败: %v", err)
	}
	return nil
}

func TerminateEC2Instance(ctx context.Context, cli *ec2.Client, id string) error {
	_, err := cli.TerminateInstances(ctx, &ec2.TerminateInstancesInput{InstanceIds: []string{id}})
	if err != nil {
		return fmt.Errorf("终止失败: %v", err)
	}
	return nil
}

func OpenAllEC2Ports(ctx context.Context, cli *ec2.Client, id string) error {
	out, err := cli.DescribeInstances(ctx, &ec2.DescribeInstancesInput{InstanceIds: []string{id}})
	if err != nil {
		return fmt.Errorf("查询实例失败: %v", err)
	}

	sgIDs := map[string]struct{}{}
	for _, reservation := range out.Reservations {
		for _, ins := range reservation.Instances {
			for _, sg := range ins.SecurityGroups {
				if sg.GroupId != nil {
					sgIDs[*sg.GroupId] = struct{}{}
				}
			}
		}
	}
	if len(sgIDs) == 0 {
		return fmt.Errorf("未找到安全组")
	}

	ipv4Perm := []ec2types.IpPermission{
		{
			IpProtocol: aws.String("-1"),
			IpRanges:   []ec2types.IpRange{{CidrIp: aws.String("0.0.0.0/0")}},
		},
	}
	ipv6Perm := []ec2types.IpPermission{
		{
			IpProtocol: aws.String("-1"),
			Ipv6Ranges: []ec2types.Ipv6Range{{CidrIpv6: aws.String("::/0")}},
		},
	}

	for sgID := range sgIDs {
		_, err = cli.AuthorizeSecurityGroupIngress(ctx, &ec2.AuthorizeSecurityGroupIngressInput{
			GroupId:       aws.String(sgID),
			IpPermissions: ipv4Perm,
		})
		if err != nil && !isDuplicatePermission(err) {
			return fmt.Errorf("开放 IPv4 入站失败: %v", err)
		}

		_, err = cli.AuthorizeSecurityGroupIngress(ctx, &ec2.AuthorizeSecurityGroupIngressInput{
			GroupId:       aws.String(sgID),
			IpPermissions: ipv6Perm,
		})
		if err != nil && !isDuplicatePermission(err) {
			return fmt.Errorf("开放 IPv6 入站失败: %v", err)
		}

		_, err = cli.AuthorizeSecurityGroupEgress(ctx, &ec2.AuthorizeSecurityGroupEgressInput{
			GroupId:       aws.String(sgID),
			IpPermissions: ipv4Perm,
		})
		if err != nil && !isDuplicatePermission(err) {
			return fmt.Errorf("开放 IPv4 出站失败: %v", err)
		}

		_, err = cli.AuthorizeSecurityGroupEgress(ctx, &ec2.AuthorizeSecurityGroupEgressInput{
			GroupId:       aws.String(sgID),
			IpPermissions: ipv6Perm,
		})
		if err != nil && !isDuplicatePermission(err) {
			return fmt.Errorf("开放 IPv6 出站失败: %v", err)
		}
	}

	return nil
}

func selectDefaultLaunchSubnet(ctx context.Context, cli *ec2.Client) (string, error) {
	vpcOut, err := cli.DescribeVpcs(ctx, &ec2.DescribeVpcsInput{
		Filters: []ec2types.Filter{{Name: aws.String("is-default"), Values: []string{"true"}}},
	})
	if err != nil {
		return "", fmt.Errorf("查询默认 VPC 失败: %v", err)
	}
	if len(vpcOut.Vpcs) == 0 {
		return "", fmt.Errorf("当前账号在该区域没有默认 VPC，无法自动选择子网")
	}

	vpcID := aws.ToString(vpcOut.Vpcs[0].VpcId)
	subnetOut, err := cli.DescribeSubnets(ctx, &ec2.DescribeSubnetsInput{
		Filters: []ec2types.Filter{{Name: aws.String("vpc-id"), Values: []string{vpcID}}},
	})
	if err != nil {
		return "", fmt.Errorf("查询默认 VPC 子网失败: %v", err)
	}
	if len(subnetOut.Subnets) == 0 {
		return "", fmt.Errorf("默认 VPC 下没有可用子网")
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

func tagCreatedEC2Instances(ctx context.Context, cli *ec2.Client, instances []ec2types.Instance, baseName string) error {
	instanceIDs := make([]string, 0, len(instances))
	for _, instance := range instances {
		id := aws.ToString(instance.InstanceId)
		if id != "" {
			instanceIDs = append(instanceIDs, id)
		}
	}
	if len(instanceIDs) <= 1 {
		return nil
	}

	sort.Strings(instanceIDs)
	width := len(fmt.Sprintf("%d", len(instanceIDs)))
	if width < 2 {
		width = 2
	}

	for idx, instanceID := range instanceIDs {
		tagValue := fmt.Sprintf("%s-%0*d", baseName, width, idx+1)
		_, err := cli.CreateTags(ctx, &ec2.CreateTagsInput{
			Resources: []string{instanceID},
			Tags:      []ec2types.Tag{{Key: aws.String("Name"), Value: aws.String(tagValue)}},
		})
		if err != nil {
			return err
		}
	}

	return nil
}

func selectIPv6Subnet(ctx context.Context, cli *ec2.Client) (string, error) {
	out, err := cli.DescribeSubnets(ctx, &ec2.DescribeSubnetsInput{})
	if err != nil {
		return "", fmt.Errorf("查询子网失败: %v", err)
	}

	type subnetInfo struct {
		ID           string
		Zone         string
		DefaultForAZ bool
	}

	var candidates []subnetInfo
	for _, subnet := range out.Subnets {
		hasIPv6 := false
		for _, assoc := range subnet.Ipv6CidrBlockAssociationSet {
			if assoc.Ipv6CidrBlockState != nil && assoc.Ipv6CidrBlockState.State == ec2types.SubnetCidrBlockStateCodeAssociated {
				hasIPv6 = true
				break
			}
		}
		if !hasIPv6 {
			continue
		}
		candidates = append(candidates, subnetInfo{
			ID:           aws.ToString(subnet.SubnetId),
			Zone:         aws.ToString(subnet.AvailabilityZone),
			DefaultForAZ: aws.ToBool(subnet.DefaultForAz),
		})
	}

	if len(candidates) == 0 {
		return ensureDefaultIPv6Subnet(ctx, cli)
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

func ensureDefaultIPv6Subnet(ctx context.Context, cli *ec2.Client) (string, error) {
	vpcOut, err := cli.DescribeVpcs(ctx, &ec2.DescribeVpcsInput{
		Filters: []ec2types.Filter{{Name: aws.String("is-default"), Values: []string{"true"}}},
	})
	if err != nil {
		return "", fmt.Errorf("查询默认 VPC 失败: %v", err)
	}
	if len(vpcOut.Vpcs) == 0 {
		return "", fmt.Errorf("当前账号没有默认 VPC，无法自动分配 IPv6 子网")
	}

	vpcID := aws.ToString(vpcOut.Vpcs[0].VpcId)
	vpcIPv6, err := ensureVpcIPv6(ctx, cli, vpcID)
	if err != nil {
		return "", err
	}

	subnetOut, err := cli.DescribeSubnets(ctx, &ec2.DescribeSubnetsInput{
		Filters: []ec2types.Filter{{Name: aws.String("vpc-id"), Values: []string{vpcID}}},
	})
	if err != nil {
		return "", fmt.Errorf("查询默认 VPC 子网失败: %v", err)
	}
	if len(subnetOut.Subnets) == 0 {
		return "", fmt.Errorf("默认 VPC 下没有可用子网")
	}

	subnetID, hasIPv6 := pickSubnetWithIPv6(subnetOut.Subnets)
	if hasIPv6 {
		return subnetID, nil
	}

	return enableSubnetIPv6(ctx, cli, subnetOut.Subnets, vpcIPv6)
}

func ensureVpcIPv6(ctx context.Context, cli *ec2.Client, vpcID string) (string, error) {
	vpc, err := describeVpc(ctx, cli, vpcID)
	if err != nil {
		return "", err
	}
	if cidr := associatedVpcIPv6(vpc); cidr != "" {
		return cidr, nil
	}

	_, err = cli.AssociateVpcCidrBlock(ctx, &ec2.AssociateVpcCidrBlockInput{
		VpcId:                       aws.String(vpcID),
		AmazonProvidedIpv6CidrBlock: aws.Bool(true),
	})
	if err != nil {
		return "", fmt.Errorf("为默认 VPC 开启 IPv6 失败: %v", err)
	}

	for i := 0; i < 10; i++ {
		time.Sleep(2 * time.Second)
		vpc, err = describeVpc(ctx, cli, vpcID)
		if err != nil {
			return "", err
		}
		if cidr := associatedVpcIPv6(vpc); cidr != "" {
			return cidr, nil
		}
	}

	return "", fmt.Errorf("默认 VPC 的 IPv6 CIDR 尚未就绪，请稍后再试")
}

func describeVpc(ctx context.Context, cli *ec2.Client, vpcID string) (ec2types.Vpc, error) {
	out, err := cli.DescribeVpcs(ctx, &ec2.DescribeVpcsInput{VpcIds: []string{vpcID}})
	if err != nil {
		return ec2types.Vpc{}, fmt.Errorf("查询 VPC 失败: %v", err)
	}
	if len(out.Vpcs) == 0 {
		return ec2types.Vpc{}, fmt.Errorf("未找到 VPC: %s", vpcID)
	}
	return out.Vpcs[0], nil
}

func associatedVpcIPv6(vpc ec2types.Vpc) string {
	for _, assoc := range vpc.Ipv6CidrBlockAssociationSet {
		if assoc.Ipv6CidrBlockState != nil && assoc.Ipv6CidrBlockState.State == ec2types.VpcCidrBlockStateCodeAssociated {
			return aws.ToString(assoc.Ipv6CidrBlock)
		}
	}
	return ""
}

func pickSubnetWithIPv6(subnets []ec2types.Subnet) (string, bool) {
	type subnetInfo struct {
		ID           string
		Zone         string
		DefaultForAZ bool
	}

	var candidates []subnetInfo
	for _, subnet := range subnets {
		hasIPv6 := false
		for _, assoc := range subnet.Ipv6CidrBlockAssociationSet {
			if assoc.Ipv6CidrBlockState != nil && assoc.Ipv6CidrBlockState.State == ec2types.SubnetCidrBlockStateCodeAssociated {
				hasIPv6 = true
				break
			}
		}
		if !hasIPv6 {
			continue
		}
		candidates = append(candidates, subnetInfo{
			ID:           aws.ToString(subnet.SubnetId),
			Zone:         aws.ToString(subnet.AvailabilityZone),
			DefaultForAZ: aws.ToBool(subnet.DefaultForAz),
		})
	}

	if len(candidates) == 0 {
		return "", false
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

	return candidates[0].ID, true
}

func enableSubnetIPv6(ctx context.Context, cli *ec2.Client, subnets []ec2types.Subnet, vpcIPv6 string) (string, error) {
	target := subnets[0]
	for _, subnet := range subnets {
		if aws.ToBool(subnet.DefaultForAz) {
			target = subnet
			break
		}
	}

	subnetID := aws.ToString(target.SubnetId)
	cidr, err := nextSubnetIPv6CIDR(vpcIPv6, subnets)
	if err != nil {
		return "", err
	}

	_, err = cli.AssociateSubnetCidrBlock(ctx, &ec2.AssociateSubnetCidrBlockInput{
		SubnetId:      aws.String(subnetID),
		Ipv6CidrBlock: aws.String(cidr),
	})
	if err != nil {
		return "", fmt.Errorf("为子网开启 IPv6 失败: %v", err)
	}

	for i := 0; i < 10; i++ {
		time.Sleep(2 * time.Second)
		subnetOut, err := cli.DescribeSubnets(ctx, &ec2.DescribeSubnetsInput{SubnetIds: []string{subnetID}})
		if err != nil {
			return "", fmt.Errorf("查询子网 IPv6 状态失败: %v", err)
		}
		if len(subnetOut.Subnets) == 0 {
			continue
		}
		for _, assoc := range subnetOut.Subnets[0].Ipv6CidrBlockAssociationSet {
			if assoc.Ipv6CidrBlockState != nil && assoc.Ipv6CidrBlockState.State == ec2types.SubnetCidrBlockStateCodeAssociated {
				return subnetID, nil
			}
		}
	}

	return "", fmt.Errorf("子网 IPv6 尚未就绪，请稍后再试")
}

func ensureSubnetIPv6Route(ctx context.Context, cli *ec2.Client, subnetID string) error {
	subnetOut, err := cli.DescribeSubnets(ctx, &ec2.DescribeSubnetsInput{SubnetIds: []string{subnetID}})
	if err != nil {
		return fmt.Errorf("查询子网失败: %v", err)
	}
	if len(subnetOut.Subnets) == 0 {
		return fmt.Errorf("未找到子网: %s", subnetID)
	}

	vpcID := aws.ToString(subnetOut.Subnets[0].VpcId)
	igwOut, err := cli.DescribeInternetGateways(ctx, &ec2.DescribeInternetGatewaysInput{
		Filters: []ec2types.Filter{{Name: aws.String("attachment.vpc-id"), Values: []string{vpcID}}},
	})
	if err != nil {
		return fmt.Errorf("查询 Internet Gateway 失败: %v", err)
	}
	if len(igwOut.InternetGateways) == 0 {
		return fmt.Errorf("当前 VPC 没有 Internet Gateway: %s", vpcID)
	}

	igwID := aws.ToString(igwOut.InternetGateways[0].InternetGatewayId)
	rtOut, err := cli.DescribeRouteTables(ctx, &ec2.DescribeRouteTablesInput{
		Filters: []ec2types.Filter{{Name: aws.String("association.subnet-id"), Values: []string{subnetID}}},
	})
	if err != nil {
		return fmt.Errorf("查询路由表失败: %v", err)
	}
	if len(rtOut.RouteTables) == 0 {
		rtOut, err = cli.DescribeRouteTables(ctx, &ec2.DescribeRouteTablesInput{
			Filters: []ec2types.Filter{
				{Name: aws.String("vpc-id"), Values: []string{vpcID}},
				{Name: aws.String("association.main"), Values: []string{"true"}},
			},
		})
		if err != nil {
			return fmt.Errorf("查询主路由表失败: %v", err)
		}
		if len(rtOut.RouteTables) == 0 {
			return fmt.Errorf("当前 VPC 没有可用路由表: %s", vpcID)
		}
	}

	routeTable := rtOut.RouteTables[0]
	for _, route := range routeTable.Routes {
		if aws.ToString(route.DestinationIpv6CidrBlock) == "::/0" && aws.ToString(route.GatewayId) == igwID {
			return nil
		}
	}

	_, err = cli.CreateRoute(ctx, &ec2.CreateRouteInput{
		RouteTableId:             routeTable.RouteTableId,
		DestinationIpv6CidrBlock: aws.String("::/0"),
		GatewayId:                aws.String(igwID),
	})
	if err != nil && !isDuplicateRoute(err) {
		return fmt.Errorf("创建 IPv6 路由失败: %v", err)
	}

	return nil
}

func nextSubnetIPv6CIDR(vpcIPv6 string, subnets []ec2types.Subnet) (string, error) {
	ip, netCIDR, err := net.ParseCIDR(vpcIPv6)
	if err != nil {
		return "", fmt.Errorf("解析 VPC IPv6 CIDR 失败: %v", err)
	}

	prefixLen, _ := netCIDR.Mask.Size()
	if prefixLen > 64 {
		return "", fmt.Errorf("VPC IPv6 前缀长度异常: %d", prefixLen)
	}

	subnetBits := 64 - prefixLen
	if subnetBits <= 0 {
		return "", fmt.Errorf("VPC IPv6 前缀长度无法生成 /64 子网: %d", prefixLen)
	}

	maxSubnets := 1 << subnetBits
	vpcFirst64 := binary.BigEndian.Uint64(ip.To16()[:8])
	prefixMask := ^uint64(0) << (64 - prefixLen)

	used := make(map[int]bool)
	for _, subnet := range subnets {
		for _, assoc := range subnet.Ipv6CidrBlockAssociationSet {
			if assoc.Ipv6CidrBlockState == nil || assoc.Ipv6CidrBlockState.State != ec2types.SubnetCidrBlockStateCodeAssociated {
				continue
			}

			subnetIP, subnetNet, err := net.ParseCIDR(aws.ToString(assoc.Ipv6CidrBlock))
			if err != nil {
				continue
			}
			subnetPrefix, _ := subnetNet.Mask.Size()
			if subnetPrefix != 64 {
				continue
			}

			subnetFirst64 := binary.BigEndian.Uint64(subnetIP.To16()[:8])
			if subnetFirst64&prefixMask != vpcFirst64&prefixMask {
				continue
			}

			index := int(subnetFirst64 & uint64(maxSubnets-1))
			used[index] = true
		}
	}

	for i := 0; i < maxSubnets; i++ {
		if used[i] {
			continue
		}
		newFirst64 := (vpcFirst64 & prefixMask) | uint64(i)
		newIP := make(net.IP, net.IPv6len)
		binary.BigEndian.PutUint64(newIP[:8], newFirst64)
		return fmt.Sprintf("%s/64", newIP.String()), nil
	}

	return "", fmt.Errorf("没有可用的 IPv6 /64 子网段")
}

func isDuplicatePermission(err error) bool {
	var apiErr smithy.APIError
	if !errors.As(err, &apiErr) {
		return false
	}
	return apiErr.ErrorCode() == "InvalidPermission.Duplicate"
}

func isDuplicateRoute(err error) bool {
	var apiErr smithy.APIError
	if !errors.As(err, &apiErr) {
		return false
	}
	code := apiErr.ErrorCode()
	return code == "RouteAlreadyExists" || code == "InvalidRoute.Duplicate"
}
