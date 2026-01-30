package aws

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/lightsail"
	"github.com/aws/aws-sdk-go-v2/service/servicequotas"
)

type LightsailAPI interface {
	GetInstances(context.Context, *lightsail.GetInstancesInput, ...func(*lightsail.Options)) (*lightsail.GetInstancesOutput, error)
	GetStaticIps(context.Context, *lightsail.GetStaticIpsInput, ...func(*lightsail.Options)) (*lightsail.GetStaticIpsOutput, error)
	DetachStaticIp(context.Context, *lightsail.DetachStaticIpInput, ...func(*lightsail.Options)) (*lightsail.DetachStaticIpOutput, error)
	ReleaseStaticIp(context.Context, *lightsail.ReleaseStaticIpInput, ...func(*lightsail.Options)) (*lightsail.ReleaseStaticIpOutput, error)
	AllocateStaticIp(context.Context, *lightsail.AllocateStaticIpInput, ...func(*lightsail.Options)) (*lightsail.AllocateStaticIpOutput, error)
	AttachStaticIp(context.Context, *lightsail.AttachStaticIpInput, ...func(*lightsail.Options)) (*lightsail.AttachStaticIpOutput, error)
	GetStaticIp(context.Context, *lightsail.GetStaticIpInput, ...func(*lightsail.Options)) (*lightsail.GetStaticIpOutput, error)
	CreateInstances(context.Context, *lightsail.CreateInstancesInput, ...func(*lightsail.Options)) (*lightsail.CreateInstancesOutput, error)
	OpenInstancePublicPorts(context.Context, *lightsail.OpenInstancePublicPortsInput, ...func(*lightsail.Options)) (*lightsail.OpenInstancePublicPortsOutput, error)
	RebootInstance(context.Context, *lightsail.RebootInstanceInput, ...func(*lightsail.Options)) (*lightsail.RebootInstanceOutput, error)
	DeleteInstance(context.Context, *lightsail.DeleteInstanceInput, ...func(*lightsail.Options)) (*lightsail.DeleteInstanceOutput, error)
}

func baseHTTPClient(proxy string) (*http.Client, error) {
	tr := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
		MaxIdleConns:    50,
		IdleConnTimeout: 30 * time.Second,
	}
	if proxy != "" {
		u, err := url.Parse(proxy)
		if err != nil {
			return nil, err
		}
		tr.Proxy = http.ProxyURL(u)
	}
	return &http.Client{Transport: tr, Timeout: 25 * time.Second}, nil
}

func NewLightsailClient(ctx context.Context, region, ak, sk, proxy string) (*lightsail.Client, error) {
	if region == "" || ak == "" || sk == "" {
		return nil, errors.New("missing region/ak/sk")
	}
	hc, err := baseHTTPClient(proxy)
	if err != nil {
		return nil, err
	}

	cfg, err := config.LoadDefaultConfig(
		ctx,
		config.WithRegion(region),
		config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(ak, sk, "")),
		config.WithHTTPClient(hc),
	)
	if err != nil {
		return nil, err
	}
	return lightsail.NewFromConfig(cfg), nil
}

func NewServiceQuotasClient(ctx context.Context, region, ak, sk, proxy string) (*servicequotas.Client, error) {
	hc, err := baseHTTPClient(proxy)
	if err != nil {
		return nil, err
	}
	cfg, err := config.LoadDefaultConfig(
		ctx,
		config.WithRegion(region),
		config.WithCredentialsProvider(aws.NewCredentialsCache(credentials.NewStaticCredentialsProvider(ak, sk, ""))),
		config.WithHTTPClient(hc),
	)
	if err != nil {
		return nil, err
	}
	return servicequotas.NewFromConfig(cfg), nil
}
