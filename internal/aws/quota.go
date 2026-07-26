package aws

import (
	"context"
	"fmt"
	"strconv"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/servicequotas"
)

// 固定 QuotaCode（EC2 vCPU）
// On-Demand Standard instances
const quotaCodeOnDemandStdVcpu = "L-1216C47A"

// Spot Standard instances
const quotaCodeSpotStdVcpu = "L-34B43A08"

// 把 *float64 转成 string：1.0 -> "1"
func floatPtrToString(v *float64) string {
	if v == nil {
		return ""
	}
	f := *v
	if f == float64(int64(f)) {
		return strconv.FormatInt(int64(f), 10)
	}
	return strconv.FormatFloat(f, 'f', -1, 64)
}

// TestVCPUQuotas：改为按 QuotaCode 直接查询（不再 list + 名称匹配）
//
// 返回值顺序保持你原来一致：
// (onVal, spotVal, onName, spotName, err)
func TestVCPUQuotas(ctx context.Context, cli *servicequotas.Client) (onVal, spotVal, onName, spotName string, err error) {
	if cli == nil {
		return "", "", "", "", fmt.Errorf("servicequotas client is nil")
	}

	// On-Demand
	onOut, e1 := cli.GetServiceQuota(ctx, &servicequotas.GetServiceQuotaInput{
		ServiceCode: aws.String("ec2"),
		QuotaCode:   aws.String(quotaCodeOnDemandStdVcpu),
	})
	if e1 == nil && onOut != nil && onOut.Quota != nil {
		onName = aws.ToString(onOut.Quota.QuotaName)
		onVal = floatPtrToString(onOut.Quota.Value)
	}

	// Spot
	spotOut, e2 := cli.GetServiceQuota(ctx, &servicequotas.GetServiceQuotaInput{
		ServiceCode: aws.String("ec2"),
		QuotaCode:   aws.String(quotaCodeSpotStdVcpu),
	})
	if e2 == nil && spotOut != nil && spotOut.Quota != nil {
		spotName = aws.ToString(spotOut.Quota.QuotaName)
		spotVal = floatPtrToString(spotOut.Quota.Value)
	}

	// 两个都没有值：把真实错误拼出来（你就能看清是 AccessDenied / region / 网络）
	if onVal == "" && spotVal == "" {
		return "", "", "", "", fmt.Errorf("配额未返回（可能无权限/region不对/网络或代理问题）：onDemandErr=%v; spotErr=%v", e1, e2)
	}

	return onVal, spotVal, onName, spotName, nil
}
