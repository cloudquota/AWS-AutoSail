package aws

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/lightsail"
	"github.com/aws/aws-sdk-go-v2/service/lightsail/types"
)

type InstanceView struct {
	Name       string
	State      string
	PublicIPv4 string
	PublicIPv6 string
	StaticIPv4 string
	Zone       string
	BundleID   string
	Created    string
}


func int32Value(v *int32) int32 {
	if v == nil {
		return 0
	}
	return *v
}

func float32Value(v *float32) float32 {
	if v == nil {
		return 0
	}
	return *v
}


func ListInstances(ctx context.Context, cli LightsailAPI) ([]InstanceView, error) {
	out, err := cli.GetInstances(ctx, &lightsail.GetInstancesInput{})
	if err != nil {
		return nil, fmt.Errorf("拉取实例失败：%v", err)
	}

	// static ips
	sipOut, _ := cli.GetStaticIps(ctx, &lightsail.GetStaticIpsInput{})
	staticMap := map[string]string{} // instanceName -> staticIPv4
	if sipOut != nil {
		for _, si := range sipOut.StaticIps {
			if si.AttachedTo != nil && si.IpAddress != nil {
				// be stricter: ensure it is actually attached
				if si.IsAttached == nil || *si.IsAttached {
					staticMap[*si.AttachedTo] = *si.IpAddress
				}
			}
		}
	}

	var list []InstanceView
	for _, ins := range out.Instances {
		name := str(ins.Name)
		state := ""
		if ins.State != nil && ins.State.Name != nil {
			state = *ins.State.Name
		}
		public4 := str(ins.PublicIpAddress)
		public6 := ""
		if len(ins.Ipv6Addresses) > 0 {
			public6 = ins.Ipv6Addresses[0]
		}

		zone := str(ins.Location.AvailabilityZone)
		created := ""
		if ins.CreatedAt != nil {
			created = ins.CreatedAt.Format("2006-01-02 15:04:05")
		}

		list = append(list, InstanceView{
			Name:       name,
			State:      state,
			PublicIPv4: public4,
			PublicIPv6: public6,
			StaticIPv4: staticMap[name],
			Zone:       zone,
			BundleID:   str(ins.BundleId),
			Created:    created,
		})
	}
	return list, nil
}

type CreateInstanceInput struct {
	InstanceName     string
	AvailabilityZone string
	BlueprintID      string
	BundleID         string
	UserData         string
	IPAddressType    string
	EnableFWAll      bool
}

func CreateInstance(ctx context.Context, cli LightsailAPI, in CreateInstanceInput) error {
	ipType := strings.TrimSpace(in.IPAddressType)
	if ipType == "" {
		ipType = "dualstack"
	}

	_, err := cli.CreateInstances(ctx, &lightsail.CreateInstancesInput{
		InstanceNames:    []string{in.InstanceName},
		AvailabilityZone: &in.AvailabilityZone,
		BlueprintId:      &in.BlueprintID,
		BundleId:         &in.BundleID,
		UserData:         &in.UserData,
		IpAddressType:    types.IpAddressType(ipType),
	})
	if err != nil {
		return fmt.Errorf("创建实例失败: %v", err)
	}

	if in.EnableFWAll {
		time.Sleep(4 * time.Second)
		_, err = cli.OpenInstancePublicPorts(ctx, &lightsail.OpenInstancePublicPortsInput{
			InstanceName: &in.InstanceName,
			PortInfo: &types.PortInfo{
				FromPort: 0,
				ToPort:   65535,
				Protocol: types.NetworkProtocolAll,
			},
		})
		if err != nil {
			return fmt.Errorf("实例已创建，但开放全端口失败: %v", err)
		}
	}

	return nil
}

func RebootInstance(ctx context.Context, cli LightsailAPI, name string) error {
	return SafeRetry("重启实例", 6, 1200*time.Millisecond, func() error {
		_, err := cli.RebootInstance(ctx, &lightsail.RebootInstanceInput{InstanceName: &name})
		return err
	})
}

func OpenAllPorts(ctx context.Context, cli LightsailAPI, instanceName string) error {
	return SafeRetry("开放全端口", 6, 1200*time.Millisecond, func() error {
		_, err := cli.OpenInstancePublicPorts(ctx, &lightsail.OpenInstancePublicPortsInput{
			InstanceName: &instanceName,
			PortInfo: &types.PortInfo{
				FromPort: 0,
				ToPort:   65535,
				Protocol: types.NetworkProtocolAll,
			},
		})
		return err
	})
}

func DeleteInstanceWithStaticIPCleanup(ctx context.Context, cli LightsailAPI, name string) error {
	_, _ = DeletePreviousStaticIPOnlyForInstance(ctx, cli, name)

	return SafeRetry("删除实例", 8, 1200*time.Millisecond, func() error {
		_, err := cli.DeleteInstance(ctx, &lightsail.DeleteInstanceInput{InstanceName: &name})
		return err
	})
}


// --- Static IP Management ---

type StaticIPView struct {
	Name       string
	IPAddress  string
	AttachedTo string
	IsAttached bool
	Region     string
	CreatedAt  string
}

func ListStaticIPs(ctx context.Context, cli LightsailAPI) ([]StaticIPView, error) {
	out, err := cli.GetStaticIps(ctx, &lightsail.GetStaticIpsInput{})
	if err != nil {
		return nil, fmt.Errorf("获取静态IP列表失败：%v", err)
	}
	var list []StaticIPView
	if out == nil {
		return list, nil
	}
	for _, si := range out.StaticIps {
		attached := false
		if si.IsAttached != nil {
			attached = *si.IsAttached
		}
		created := ""
		if si.CreatedAt != nil {
			created = si.CreatedAt.Format("2006-01-02 15:04:05")
		}
		region := ""
		if si.Location != nil {
			region = string(si.Location.RegionName)
		}
		list = append(list, StaticIPView{
			Name:       str(si.Name),
			IPAddress:  str(si.IpAddress),
			AttachedTo: str(si.AttachedTo),
			IsAttached: attached,
			Region:     region,
			CreatedAt:  created,
		})
	}
	return list, nil
}

func AllocateNewStaticIP(ctx context.Context, cli LightsailAPI, name string) error {
	return SafeRetry("分配静态IP", 6, 1200*time.Millisecond, func() error {
		_, err := cli.AllocateStaticIp(ctx, &lightsail.AllocateStaticIpInput{StaticIpName: &name})
		return err
	})
}

func DeleteStaticIP(ctx context.Context, cli LightsailAPI, name string) error {
	// Check if attached; detach first
	out, err := cli.GetStaticIp(ctx, &lightsail.GetStaticIpInput{StaticIpName: &name})
	if err != nil {
		return fmt.Errorf("获取静态IP信息失败：%v", err)
	}
	if out != nil && out.StaticIp != nil && out.StaticIp.IsAttached != nil && *out.StaticIp.IsAttached {
		if err := SafeRetry("解绑静态IP", 8, 1200*time.Millisecond, func() error {
			_, err := cli.DetachStaticIp(ctx, &lightsail.DetachStaticIpInput{StaticIpName: &name})
			return err
		}); err != nil {
			return fmt.Errorf("解绑失败：%v", err)
		}
		WaitStaticIPDetached(ctx, cli, name, 60*time.Second)
	}
	return SafeRetry("释放静态IP", 8, 1200*time.Millisecond, func() error {
		_, err := cli.ReleaseStaticIp(ctx, &lightsail.ReleaseStaticIpInput{StaticIpName: &name})
		return err
	})
}

func AttachStaticIPToInstance(ctx context.Context, cli LightsailAPI, staticIPName, instanceName string) error {
	return SafeRetry("附加静态IP", 8, 1200*time.Millisecond, func() error {
		_, err := cli.AttachStaticIp(ctx, &lightsail.AttachStaticIpInput{
			StaticIpName: &staticIPName,
			InstanceName: &instanceName,
		})
		return err
	})
}

func DetachStaticIPFromInstance(ctx context.Context, cli LightsailAPI, staticIPName string) error {
	return SafeRetry("解绑静态IP", 8, 1200*time.Millisecond, func() error {
		_, err := cli.DetachStaticIp(ctx, &lightsail.DetachStaticIpInput{StaticIpName: &staticIPName})
		return err
	})
}

func WaitStaticIPDetached(ctx context.Context, cli LightsailAPI, staticIPName string, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		out, err := cli.GetStaticIp(ctx, &lightsail.GetStaticIpInput{StaticIpName: &staticIPName})
		if err != nil || out == nil || out.StaticIp == nil {
			// gone -> detached+released maybe
			return true
		}
		if out.StaticIp.IsAttached != nil && !*out.StaticIp.IsAttached {
			return true
		}
		if out.StaticIp.AttachedTo == nil || *out.StaticIp.AttachedTo == "" {
			return true
		}
		time.Sleep(2 * time.Second)
	}
	return false
}

func str[T ~string](p *T) string {
	if p == nil {
		return ""
	}
	return string(*p)
}

func SwapStaticIPForInstance(ctx context.Context, cli LightsailAPI, instanceName string) error {
	// sanity: ipv6-only instances cannot use IPv4 Static IP
	insOut, err := cli.GetInstances(ctx, &lightsail.GetInstancesInput{})
	if err == nil && insOut != nil {
		for _, ins := range insOut.Instances {
			if str(ins.Name) == instanceName {
				if str(ins.PublicIpAddress) == "" {
					return fmt.Errorf("该实例无公网 IPv4（可能是 IPv6-only），无法换静态IP")
				}
				break
			}
		}
	}

	// detach/release old
	oldName, cleanErr := DeletePreviousStaticIPOnlyForInstance(ctx, cli, instanceName)
	if cleanErr != nil {
		fmt.Printf("[SwapIP] 清理旧静态IP失败（继续创建新IP）: %v\n", cleanErr)
	} else if oldName != "" {
		fmt.Printf("[SwapIP] 已释放旧静态IP: %s\n", oldName)
	}

	// allocate new and attach
	newName := fmt.Sprintf("sip-%s-%d", sanitize(instanceName), time.Now().Unix())
	if err := SafeRetry("申请新静态IP", 8, 1200*time.Millisecond, func() error {
		_, err := cli.AllocateStaticIp(ctx, &lightsail.AllocateStaticIpInput{StaticIpName: &newName})
		return err
	}); err != nil {
		return err
	}

	if err := SafeRetry("绑定新静态IP", 8, 1200*time.Millisecond, func() error {
		_, err := cli.AttachStaticIp(ctx, &lightsail.AttachStaticIpInput{
			StaticIpName: &newName,
			InstanceName: &instanceName,
		})
		return err
	}); err != nil {
		return err
	}

	return nil
}

func DeletePreviousStaticIPOnlyForInstance(ctx context.Context, cli LightsailAPI, instanceName string) (string, error) {
	oldName, _ := FindAttachedStaticIPName(ctx, cli, instanceName)
	if oldName == "" {
		return "", nil
	}

	if err := SafeRetry("解绑旧静态IP", 8, 1200*time.Millisecond, func() error {
		_, err := cli.DetachStaticIp(ctx, &lightsail.DetachStaticIpInput{StaticIpName: &oldName})
		return err
	}); err != nil {
		return "", err
	}

	ok := WaitStaticIPDetached(ctx, cli, oldName, 120*time.Second)
	if !ok {
		return "", fmt.Errorf("旧静态IP解绑超时：%s", oldName)
	}

	if err := SafeRetry("释放旧静态IP", 12, 1300*time.Millisecond, func() error {
		_, err := cli.ReleaseStaticIp(ctx, &lightsail.ReleaseStaticIpInput{StaticIpName: &oldName})
		return err
	}); err != nil {
		return "", err
	}

	// wait deleted
	deadline := time.Now().Add(90 * time.Second)
	for time.Now().Before(deadline) {
		_, err := cli.GetStaticIp(ctx, &lightsail.GetStaticIpInput{StaticIpName: &oldName})
		if err != nil {
			// not found is enough
			return oldName, nil
		}
		time.Sleep(2 * time.Second)
	}
	return "", fmt.Errorf("旧静态IP仍存在（释放未生效）：%s", oldName)
}

func FindAttachedStaticIPName(ctx context.Context, cli LightsailAPI, instanceName string) (string, string) {
	out, err := cli.GetStaticIps(ctx, &lightsail.GetStaticIpsInput{})
	if err != nil || out == nil {
		return "", ""
	}
	for _, si := range out.StaticIps {
		if si.AttachedTo != nil && *si.AttachedTo == instanceName {
			if si.IsAttached == nil || *si.IsAttached {
				return str(si.Name), str(si.IpAddress)
			}
		}
	}
	return "", ""
}

func sanitize(s string) string {
	s = strings.ToLower(s)
	var b strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
			b.WriteRune(r)
		}
	}
	out := b.String()
	if out == "" {
		return "x"
	}
	return out
}

func BuildRootPasswordUserData(password string) string {
	pw := base64.StdEncoding.EncodeToString([]byte(password))
	return fmt.Sprintf(`#!/bin/bash
set -e

if [[ $(id -u) != 0 ]]; then
  echo "must run as root"
  exit 1
fi

password_b64="%s"
password="$(printf '%%s' "$password_b64" | base64 -d)"

echo "root:$password" | chpasswd
passwd -u root || true

sed -i 's@^\(Include[ ]*/etc/ssh/sshd_config.d/\*\.conf\)@# \1@' /etc/ssh/sshd_config
sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin yes/g;s/^#\?PasswordAuthentication.*/PasswordAuthentication yes/g' /etc/ssh/sshd_config
sed -i 's/^#\?PubkeyAuthentication.*/PubkeyAuthentication no/g' /etc/ssh/sshd_config
sed -i '/^AuthorizedKeysFile/s/^/#/' /etc/ssh/sshd_config
sed -i 's/^#[[:space:]]*KbdInteractiveAuthentication.*\|^KbdInteractiveAuthentication.*/KbdInteractiveAuthentication yes/' /etc/ssh/sshd_config

if [ -f /etc/os-release ]; then
  if [ "$(awk -F= '/VERSION_CODENAME/{print $2}' /etc/os-release)" = 'noble' ]; then
    systemctl restart ssh || true
  elif [[ "$(grep 'PRETTY_NAME' /etc/os-release)" =~ 'Alpine' ]]; then
    service sshd restart || true
  else
    systemctl restart sshd || true
  fi
else
  systemctl restart ssh >/dev/null 2>&1 || true
  systemctl restart sshd >/dev/null 2>&1 || true
  service sshd restart >/dev/null 2>&1 || true
fi
`, pw)
}
