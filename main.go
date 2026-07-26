package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/gin-gonic/gin"
	"github.com/patrickmn/go-cache"

	"aws-lightsail-go/internal/auth"
	"aws-lightsail-go/internal/aws"
	"aws-lightsail-go/internal/session"
)

type Flash struct {
	Success string
	Error   string
	Warn    string
	Info    string
}

type PageData struct {
	Title string

	Region  string
	Regions []RegionOption

	Tab string

	Flash Flash

	ActiveAccount  string

	// Lightsail create/manage
	HasCreateCreds   bool
	HasManageCreds   bool
	CreateService    string
	ManageService    string
	CreateEnableFW   bool
	CreateIPType     string
	CreateBlueprint  string
	CreateBundle     string
	CreateRootPwd    string
	CreateEC2AMI     string
	CreateEC2Type    string
	CreateEC2Count   int
	CreateEC2IPv6    bool
	CreateRegions    []RegionOption
	ManageRegions    []RegionOption
	Blueprints       []Option
	Bundles          []Option
	IPTypes          []Option
	EC2AMIs          []Option
	EC2Types         []Option
	Instances        []aws.InstanceView
	EC2Instances     []aws.EC2InstanceView
	SpecialRegions   []RegionOption

	// Quota
	QuotaRegion string
	QuotaOn     string
	QuotaSpot   string
	QuotaOnName string
	QuotaSpName string

	HasQuotaCreds bool
	QuotaAccount  string
	Accounts      []auth.AWSAccount
	AWSAccounts   []AWSAccountCard
	AWSPage       int
	AWSPageSize   int
	AWSTotal      int
	AWSTotalPages int
	AWSHasPrev    bool
	AWSHasNext    bool
	AWSPrevPage   int
	AWSNextPage   int

	// Settings
	CfgUsername string

	// Login page
	Username string
	Error    string
}

type QuotaSnapshot struct {
	Region      string
	OnDemand    string
	Spot        string
	OnDemandMsg string
	SpotMsg     string
	UpdatedAt   time.Time
}

type AWSAccountCard struct {
	auth.AWSAccount
	QuotaRegion  string
	QuotaOn      string
	QuotaSpot    string
	QuotaOnName  string
	QuotaSpName  string
	QuotaUpdated string
	HasQuota     bool
}

type Option struct {
	ID   string
	Name string
}

var (
	quotaCache  = cache.New(10*time.Minute, 20*time.Minute)
	instCache   = cache.New(10*time.Second, 30*time.Second)
	bundleCache = cache.New(10*time.Minute, 20*time.Minute)

	activeNewbieTask *aws.NewbieTaskEngine
	newbieTaskMu     sync.Mutex
)

const awsAccountPageSize = 6

type RegionOption struct {
	ID   string
	Name string
}

var (
	accessKeyPattern = regexp.MustCompile(`\b(?:AKIA|ASIA)[A-Z0-9]{16}\b`)
	secretKeyPattern = regexp.MustCompile(`^[A-Za-z0-9/+=]{30,128}$`)
	regionIDPattern  = regexp.MustCompile(`^[a-z]{2}(?:-[a-z]+)+-\d$`)
)



func mustEnvInt(key string, def int) int {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return def
	}
	i, err := strconv.Atoi(v)
	if err != nil {
		return def
	}
	return i
}

func mustSessionInt(v string, def int) int {
	v = strings.TrimSpace(v)
	if v == "" {
		return def
	}
	i, err := strconv.Atoi(v)
	if err != nil || i <= 0 {
		return def
	}
	return i
}

func clampInt(v, minV, maxV int) int {
	if v < minV {
		return minV
	}
	if v > maxV {
		return maxV
	}
	return v
}

func generateRandomPassword(length int) string {
	const charset = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789@#_-"
	if length <= 0 {
		length = 16
	}

	buf := make([]byte, length)
	raw := make([]byte, length)
	if _, err := rand.Read(raw); err != nil {
		return "AwsRoot@" + strconv.FormatInt(time.Now().Unix()%1000000, 10)
	}

	for i := range buf {
		buf[i] = charset[int(raw[i])%len(charset)]
	}
	return string(buf)
}

func generateRandomAccountName() string {
	const charset = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	buf := make([]byte, 6)
	raw := make([]byte, len(buf))
	if _, err := rand.Read(raw); err != nil {
		return "aws-auto-" + strconv.FormatInt(time.Now().Unix()%1000000, 10)
	}
	for i := range buf {
		buf[i] = charset[int(raw[i])%len(charset)]
	}
	return "aws-auto-" + strings.ToLower(string(buf))
}

func cleanAccountToken(v string) string {
	v = strings.TrimSpace(v)
	v = strings.Trim(v, "\"'")
	if idx := strings.Index(v, ":"); idx > 0 {
		key := strings.ToLower(strings.TrimSpace(v[:idx]))
		switch key {
		case "name", "账号", "账户", "acct", "account", "access key", "ak", "secret key", "sk", "proxy", "region", "地区", "区域":
			v = strings.TrimSpace(v[idx+1:])
		}
	}
	return strings.TrimSpace(strings.Trim(v, "\"'"))
}

func looksLikeRegion(v string) bool {
	return regionIDPattern.MatchString(strings.TrimSpace(strings.ToLower(v)))
}

func looksLikeProxy(v string) bool {
	v = strings.ToLower(strings.TrimSpace(v))
	return strings.HasPrefix(v, "http://") || strings.HasPrefix(v, "https://") || strings.HasPrefix(v, "socks5://") || strings.HasPrefix(v, "socks5h://")
}

func looksLikeSecretKey(v string) bool {
	v = strings.TrimSpace(v)
	if looksLikeProxy(v) || looksLikeRegion(v) || accessKeyPattern.MatchString(v) {
		return false
	}
	return secretKeyPattern.MatchString(v)
}

func splitBulkAccountEntries(raw string) []string {
	raw = strings.ReplaceAll(raw, "\r\n", "\n")
	raw = strings.ReplaceAll(raw, "\r", "\n")
	if strings.TrimSpace(raw) == "" {
		return nil
	}

	blocks := strings.Split(raw, "\n\n")
	entries := make([]string, 0, len(blocks))
	for _, block := range blocks {
		block = strings.TrimSpace(block)
		if block == "" {
			continue
		}
		if strings.Count(block, "\n") == 0 {
			entries = append(entries, block)
			continue
		}
		if accessKeyPattern.MatchString(block) && strings.Count(block, "\n") == 1 {
			entries = append(entries, block)
			continue
		}
		lines := strings.Split(block, "\n")
		lineHasAK := 0
		for _, line := range lines {
			if accessKeyPattern.MatchString(line) {
				lineHasAK++
			}
		}
		if lineHasAK > 1 {
			for _, line := range lines {
				line = strings.TrimSpace(line)
				if line != "" {
					entries = append(entries, line)
				}
			}
			continue
		}
		entries = append(entries, block)
	}
	return entries
}

func parseBulkAccountEntry(entry, defaultProxy, defaultRegion string, index int) (auth.AWSAccount, bool) {
	entry = strings.TrimSpace(entry)
	if entry == "" {
		return auth.AWSAccount{}, false
	}

	defaultRegion = normalizeRegion(defaultRegion)
	if defaultRegion == "" {
		defaultRegion = "us-east-1"
	}

	var (
		name   string
		ak     string
		sk     string
		proxy  = strings.TrimSpace(defaultProxy)
		region = defaultRegion
	)

	parts := make([]string, 0)
	if strings.ContainsAny(entry, ",|\t;") {
		fields := strings.FieldsFunc(entry, func(r rune) bool {
			return r == ',' || r == '|' || r == '\t' || r == ';'
		})
		for _, field := range fields {
			token := cleanAccountToken(field)
			if token != "" {
				parts = append(parts, token)
			}
		}
	} else {
		lines := strings.Split(entry, "\n")
		for _, line := range lines {
			token := cleanAccountToken(line)
			if token != "" {
				parts = append(parts, token)
			}
		}
	}

	for _, token := range parts {
		switch {
		case ak == "" && accessKeyPattern.MatchString(token):
			ak = accessKeyPattern.FindString(token)
		case sk == "" && looksLikeSecretKey(token):
			sk = token
		case proxy == "" && looksLikeProxy(token):
			proxy = token
		case region == defaultRegion && looksLikeRegion(token):
			region = normalizeRegion(token)
		case name == "":
			name = token
		}
	}

	if ak == "" {
		ak = accessKeyPattern.FindString(entry)
	}
	if sk == "" {
		for _, token := range strings.FieldsFunc(strings.ReplaceAll(entry, "\n", " "), func(r rune) bool {
			return r == ' ' || r == ',' || r == '|' || r == '\t' || r == ';'
		}) {
			token = cleanAccountToken(token)
			if looksLikeSecretKey(token) {
				sk = token
				break
			}
		}
	}
	if proxy == "" {
		for _, token := range parts {
			if looksLikeProxy(token) {
				proxy = token
				break
			}
		}
	}
	if region == defaultRegion {
		for _, token := range parts {
			if looksLikeRegion(token) {
				region = normalizeRegion(token)
				break
			}
		}
	}

	if ak == "" || sk == "" {
		return auth.AWSAccount{}, false
	}
	if name == "" || accessKeyPattern.MatchString(name) || looksLikeSecretKey(name) || looksLikeProxy(name) || looksLikeRegion(name) {
		name = generateRandomAccountName()
	}
	if region == "" {
		region = "us-east-1"
	}

	return auth.AWSAccount{
		Name:   name,
		AK:     ak,
		SK:     sk,
		Proxy:  strings.TrimSpace(proxy),
		Region: region,
	}, true
}

func ensureUniqueAccountName(name string, used map[string]struct{}) string {
	name = strings.TrimSpace(name)
	if name == "" {
		name = generateRandomAccountName()
	}
	candidate := name
	for i := 2; ; i++ {
		key := strings.ToLower(candidate)
		if _, exists := used[key]; !exists {
			used[key] = struct{}{}
			return candidate
		}
		candidate = fmt.Sprintf("%s-%d", name, i)
	}
}

func parseBulkAWSAccounts(raw, defaultProxy, defaultRegion string, existing []auth.AWSAccount) []auth.AWSAccount {
	entries := splitBulkAccountEntries(raw)
	if len(entries) == 0 {
		return nil
	}

	used := make(map[string]struct{}, len(existing)+len(entries))
	for _, acct := range existing {
		used[strings.ToLower(strings.TrimSpace(acct.Name))] = struct{}{}
	}

	accounts := make([]auth.AWSAccount, 0, len(entries))
	for idx, entry := range entries {
		acct, ok := parseBulkAccountEntry(entry, defaultProxy, defaultRegion, idx)
		if !ok {
			continue
		}
		acct.Name = ensureUniqueAccountName(acct.Name, used)
		if acct.Region == "" {
			acct.Region = "us-east-1"
		}
		accounts = append(accounts, acct)
	}
	return accounts
}

var regionOptions = []RegionOption{
	{ID: "ap-east-1", Name: "香港 Hong Kong"},
	{ID: "ap-northeast-1", Name: "东京 Tokyo"},
	{ID: "ap-northeast-2", Name: "首尔 Seoul"},
	{ID: "ap-southeast-1", Name: "新加坡 Singapore"},
	{ID: "ap-southeast-2", Name: "悉尼 Sydney"},
	{ID: "ap-south-1", Name: "孟买 Mumbai"},
	{ID: "us-east-1", Name: "弗吉尼亚 N. Virginia"},
	{ID: "us-east-2", Name: "俄亥俄 Ohio"},
	{ID: "us-west-2", Name: "俄勒冈 Oregon"},
	{ID: "ca-central-1", Name: "加拿大（中部） Canada Central"},
	{ID: "eu-central-1", Name: "法兰克福 Frankfurt"},
	{ID: "eu-west-1", Name: "爱尔兰 Ireland"},
	{ID: "eu-west-2", Name: "伦敦 London"},
	{ID: "eu-west-3", Name: "巴黎 Paris"},
	{ID: "eu-north-1", Name: "斯德哥尔摩 Stockholm"},
}

var ec2RegionOptions = []RegionOption{
	{ID: "af-south-1", Name: "开普敦 Cape Town"},
	{ID: "ap-east-1", Name: "香港 Hong Kong"},
	{ID: "ap-northeast-1", Name: "东京 Tokyo"},
	{ID: "ap-northeast-2", Name: "首尔 Seoul"},
	{ID: "ap-northeast-3", Name: "大阪 Osaka"},
	{ID: "ap-south-1", Name: "孟买 Mumbai"},
	{ID: "ap-south-2", Name: "海得拉巴 Hyderabad"},
	{ID: "ap-southeast-1", Name: "新加坡 Singapore"},
	{ID: "ap-southeast-2", Name: "悉尼 Sydney"},
	{ID: "ap-southeast-3", Name: "雅加达 Jakarta"},
	{ID: "ap-southeast-4", Name: "墨尔本 Melbourne"},
	{ID: "ca-central-1", Name: "加拿大（中部） Canada Central"},
	{ID: "ca-west-1", Name: "加拿大（西部） Canada West"},
	{ID: "eu-central-1", Name: "法兰克福 Frankfurt"},
	{ID: "eu-central-2", Name: "苏黎世 Zurich"},
	{ID: "eu-north-1", Name: "斯德哥尔摩 Stockholm"},
	{ID: "eu-south-1", Name: "米兰 Milan"},
	{ID: "eu-south-2", Name: "西班牙 Spain"},
	{ID: "eu-west-1", Name: "爱尔兰 Ireland"},
	{ID: "eu-west-2", Name: "伦敦 London"},
	{ID: "eu-west-3", Name: "巴黎 Paris"},
	{ID: "il-central-1", Name: "以色列（中部） Israel"},
	{ID: "me-central-1", Name: "阿联酋 UAE"},
	{ID: "me-south-1", Name: "巴林 Bahrain"},
	{ID: "sa-east-1", Name: "圣保罗 Sao Paulo"},
	{ID: "us-east-1", Name: "弗吉尼亚 N. Virginia"},
	{ID: "us-east-2", Name: "俄亥俄 Ohio"},
	{ID: "us-west-1", Name: "北加州 N. California"},
	{ID: "us-west-2", Name: "俄勒冈 Oregon"},
}

var specialRegionOptions = []RegionOption{
	{ID: "ap-east-1", Name: "香港 Hong Kong"},
}

var blueprintOptions = []Option{
	{ID: "ubuntu_24_04", Name: "Ubuntu 24.04 LTS"},
	{ID: "ubuntu_22_04", Name: "Ubuntu 22.04 LTS"},
	{ID: "debian_12", Name: "Debian 12"},
	{ID: "amazon_linux_2023", Name: "Amazon Linux 2023"},
	{ID: "debian_11", Name: "Debian 11"},
}

var bundleOptions = []Option{
	{ID: "nano_3_0", Name: "nano 3.0 (2 vCPUs, 0.5 GB 内存, 20 GB 磁盘, 1024 GB 流量)"},
	{ID: "micro_3_0", Name: "micro 3.0 (2 vCPUs, 1 GB 内存, 40 GB 磁盘, 2048 GB 流量)"},
	{ID: "small_3_0", Name: "small 3.0 (2 vCPUs, 2 GB 内存, 60 GB 磁盘, 3072 GB 流量)"},
	{ID: "medium_3_0", Name: "medium 3.0 (2 vCPUs, 4 GB 内存, 80 GB 磁盘, 4096 GB 流量)"},
	{ID: "large_3_0", Name: "large 3.0 (2 vCPUs, 8 GB 内存, 160 GB 磁盘, 5120 GB 流量)"},
}

var hongKongBundleOptions = []Option{
	{ID: "nano_5_0", Name: "nano 5.0 (2 vCPUs, 0.5 GB 内存, 20 GB 磁盘, 1024 GB 流量)"},
	{ID: "micro_5_0", Name: "micro 5.0 (2 vCPUs, 1 GB 内存, 40 GB 磁盘, 2048 GB 流量)"},
	{ID: "small_5_0", Name: "small 5.0 (2 vCPUs, 2 GB 内存, 60 GB 磁盘, 3072 GB 流量)"},
	{ID: "medium_5_0", Name: "medium 5.0 (2 vCPUs, 4 GB 内存, 80 GB 磁盘, 4096 GB 流量)"},
	{ID: "large_5_0", Name: "large 5.0 (2 vCPUs, 8 GB 内存, 160 GB 磁盘, 5120 GB 流量)"},
	{ID: "xlarge_5_0", Name: "xlarge 5.0 (4 vCPUs, 16 GB 内存, 320 GB 磁盘, 6144 GB 流量)"},
	{ID: "2xlarge_5_0", Name: "2xlarge 5.0 (8 vCPUs, 32 GB 内存, 640 GB 磁盘, 7168 GB 流量)"},
}

var ipTypeOptions = []Option{
	{ID: "dualstack", Name: "双栈（IPv4 + IPv6）"},
	{ID: "ipv6", Name: "仅 IPv6（IPv6 only）"},
	{ID: "ipv4", Name: "仅 IPv4"},
}

var ec2AMIOptions = []Option{
	{ID: "ubuntu-24.04", Name: "Ubuntu 24.04 LTS"},
	{ID: "ubuntu-22.04", Name: "Ubuntu 22.04 LTS"},
	{ID: "debian-12", Name: "Debian 12"},
	{ID: "amzn-2023", Name: "Amazon Linux 2023"},
}

var ec2InstanceTypeOptions = []Option{
	{ID: "t3.micro", Name: "t3.micro (2 vCPU, 1 GB)"},
	{ID: "t3.small", Name: "t3.small (2 vCPU, 2 GB)"},
	{ID: "t3.medium", Name: "t3.medium (2 vCPU, 4 GB)"},
	{ID: "t3.large", Name: "t3.large (2 vCPU, 8 GB)"},
	{ID: "t3a.micro", Name: "t3a.micro (2 vCPU, 1 GB)"},
	{ID: "t3a.small", Name: "t3a.small (2 vCPU, 2 GB)"},
	{ID: "t3a.medium", Name: "t3a.medium (2 vCPU, 4 GB)"},
	{ID: "m6i.large", Name: "m6i.large (2 vCPU, 8 GB)"},
	{ID: "c6i.large", Name: "c6i.large (2 vCPU, 4 GB)"},
	{ID: "r6i.large", Name: "r6i.large (2 vCPU, 16 GB)"},
}

var ipv6BundleMap = map[string]string{
	// 标准区域 _3_0 系列
	"nano_3_0":   "nano_ipv6_3_0",
	"micro_3_0":  "micro_ipv6_3_0",
	"small_3_0":  "small_ipv6_3_0",
	"medium_3_0": "medium_ipv6_3_0",
	"large_3_0":  "large_ipv6_3_0",
	// 香港旧版 _4_0 系列（兼容性保留）
	"nano_4_0":   "nano_ipv6_4_0",
	"micro_4_0":  "micro_ipv6_4_0",
	"small_4_0":  "small_ipv6_4_0",
	"medium_4_0": "medium_ipv6_4_0",
	"large_4_0":  "large_ipv6_4_0",
	// 香港新版 _5_0 系列
	"nano_5_0":    "nano_ipv6_5_0",
	"micro_5_0":   "micro_ipv6_5_0",
	"small_5_0":   "small_ipv6_5_0",
	"medium_5_0":  "medium_ipv6_5_0",
	"large_5_0":   "large_ipv6_5_0",
	"xlarge_5_0":  "xlarge_ipv6_5_0",
	"2xlarge_5_0": "2xlarge_ipv6_5_0",
}

func firstOptionID(list []Option) string {
	if len(list) == 0 {
		return ""
	}
	return list[0].ID
}

func lightsailBundleDisplayID(id string) string {
	parts := strings.Split(id, "_")
	if len(parts) >= 3 {
		return parts[0] + " " + parts[1] + "." + parts[2]
	}
	return id
}

func lightsailBundleLabel(bundle aws.BundleView) string {
	name := lightsailBundleDisplayID(bundle.ID)
	if bundle.CPUCount <= 0 || bundle.RAMSizeGB <= 0 || bundle.DiskSizeGB <= 0 {
		return name
	}
	ram := strconv.FormatFloat(float64(bundle.RAMSizeGB), 'f', -1, 32)
	if bundle.TransferPerMonthGB > 0 {
		return fmt.Sprintf("%s (%d vCPUs, %s GB 内存, %d GB 磁盘, %d GB 流量)", name, bundle.CPUCount, ram, bundle.DiskSizeGB, bundle.TransferPerMonthGB)
	}
	return fmt.Sprintf("%s (%d vCPUs, %s GB 内存, %d GB 磁盘)", name, bundle.CPUCount, ram, bundle.DiskSizeGB)
}

func loadLightsailBundleOptions(ctx context.Context, acct auth.AWSAccount, region string) []Option {
	fallback := bundleOptionsForRegion(region)
	region = normalizeRegion(region)
	if region == "" || strings.TrimSpace(acct.AK) == "" || strings.TrimSpace(acct.SK) == "" {
		return fallback
	}

	cacheKey := "lightsail_bundles:" + region
	if cached, ok := bundleCache.Get(cacheKey); ok {
		if options, ok := cached.([]Option); ok && len(options) > 0 {
			return options
		}
	}

	// Use a short timeout to avoid blocking page load when region is not activated
	bundleCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	cli, err := aws.NewLightsailClient(bundleCtx, region, acct.AK, acct.SK, acct.Proxy)
	if err != nil {
		return fallback
	}
	bundles, err := aws.ListBundles(bundleCtx, cli)
	if err != nil || len(bundles) == 0 {
		return fallback
	}

	options := make([]Option, 0, len(bundles))
	for _, bundle := range bundles {
		id := strings.TrimSpace(bundle.ID)
		if id == "" || strings.Contains(id, "_ipv6_") {
			continue
		}
		options = append(options, Option{ID: id, Name: lightsailBundleLabel(bundle)})
	}
	if len(options) == 0 {
		return fallback
	}
	bundleCache.Set(cacheKey, options, cache.DefaultExpiration)
	return options
}
func regionLabel(id string) string {
	for _, r := range allRegionOptions() {
		if r.ID == id {
			return r.Name
		}
	}
	return id
}

func regionOptionsForService(service string) []RegionOption {
	if strings.TrimSpace(service) == "ec2" {
		return ec2RegionOptions
	}
	return regionOptions
}

func bundleOptionsForRegion(region string) []Option {
	if normalizeRegion(region) == "ap-east-1" {
		return hongKongBundleOptions
	}
	return bundleOptions
}

func defaultBundleForRegion(region string) string {
	bundles := bundleOptionsForRegion(region)
	if len(bundles) == 0 {
		return ""
	}
	return bundles[0].ID
}

func normalizeLightsailBundleForRegion(region, bundle string) string {
	bundle = strings.TrimSpace(bundle)
	if normalizeRegion(region) == "ap-east-1" {
		// 香港使用 _5_0 bundle；兼容旧版 _3_0 / _4_0 切换过来的情况
		bundle = strings.Replace(bundle, "_3_0", "_5_0", 1)
		bundle = strings.Replace(bundle, "_4_0", "_5_0", 1)
	} else {
		// 其他区域使用 _3_0 bundle；从香港切换回来时还原
		bundle = strings.Replace(bundle, "_5_0", "_3_0", 1)
		bundle = strings.Replace(bundle, "_4_0", "_3_0", 1)
	}
	return bundle
}

func allRegionOptions() []RegionOption {
	all := make([]RegionOption, 0, len(regionOptions)+len(ec2RegionOptions))
	all = append(all, regionOptions...)
	for _, r := range ec2RegionOptions {
		if !containsRegion(all, r.ID) {
			all = append(all, r)
		}
	}
	return all
}

func containsRegion(list []RegionOption, id string) bool {
	for _, item := range list {
		if item.ID == id {
			return true
		}
	}
	return false
}

func containsOption(list []Option, id string) bool {
	for _, item := range list {
		if item.ID == id {
			return true
		}
	}
	return false
}
func normalizeRegion(r string) string {
	r = strings.TrimSpace(r)
	if r == "a" || r == "b" || r == "c" {
		return "us-east-1"
	}
	if len(r) >= 2 {
		last := r[len(r)-1]
		if (last == 'a' || last == 'b' || last == 'c') && strings.Contains(r, "-") {
			p := r[len(r)-2]
			if p >= '0' && p <= '9' {
				return r[:len(r)-1]
			}
		}
	}
	return r
}

func quotaCacheKey(accountName, region string) string {
	return strings.ToLower(strings.TrimSpace(accountName)) + "|" + normalizeRegion(region)
}

func quotaRegionSessionKey(accountName string) string {
	return "quota_region:" + strings.ToLower(strings.TrimSpace(accountName))
}

func actionAccountSessionKey(tab string) string {
	return "selected_account:" + strings.TrimSpace(tab)
}

func activeAccountSessionKey() string {
	return actionAccountSessionKey("active")
}

func setActiveAccount(s *session.Session, accountName string) {
	accountName = strings.TrimSpace(accountName)
	if accountName == "" {
		return
	}
	s.SetString(activeAccountSessionKey(), accountName)
	s.SetString(actionAccountSessionKey("create"), accountName)
	s.SetString(actionAccountSessionKey("manage"), accountName)
}

func clearActiveAccount(s *session.Session) {
	s.SetString(activeAccountSessionKey(), "")
	s.SetString(actionAccountSessionKey("create"), "")
	s.SetString(actionAccountSessionKey("manage"), "")
}

func syncSessionAccountRename(s *session.Session, oldName, newName string) {
	oldName = strings.TrimSpace(oldName)
	newName = strings.TrimSpace(newName)
	if oldName == "" || newName == "" || oldName == newName {
		return
	}

	if strings.TrimSpace(s.GetString(activeAccountSessionKey(), "")) == oldName {
		s.SetString(activeAccountSessionKey(), newName)
	}
	if strings.TrimSpace(s.GetString(actionAccountSessionKey("create"), "")) == oldName {
		s.SetString(actionAccountSessionKey("create"), newName)
	}
	if strings.TrimSpace(s.GetString(actionAccountSessionKey("manage"), "")) == oldName {
		s.SetString(actionAccountSessionKey("manage"), newName)
	}
	if strings.TrimSpace(s.GetString("quota_account", "")) == oldName {
		s.SetString("quota_account", newName)
	}
}

func syncSessionAccountRemoval(s *session.Session, cfgMgr *auth.ConfigManager, removedName string) {
	removedName = strings.TrimSpace(removedName)
	if removedName == "" {
		return
	}

	if strings.TrimSpace(s.GetString(activeAccountSessionKey(), "")) == removedName ||
		strings.TrimSpace(s.GetString(actionAccountSessionKey("create"), "")) == removedName ||
		strings.TrimSpace(s.GetString(actionAccountSessionKey("manage"), "")) == removedName {
		clearActiveAccount(s)
	}

	if strings.TrimSpace(s.GetString("quota_account", "")) == removedName {
		accounts := cfgMgr.GetAccounts()
		if len(accounts) > 0 {
			s.SetString("quota_account", accounts[0].Name)
		} else {
			s.SetString("quota_account", "")
		}
	}
}

func storeQuotaSnapshot(accountName, region string, snap QuotaSnapshot) {
	quotaCache.Set(quotaCacheKey(accountName, region), snap, cache.DefaultExpiration)
}

func loadQuotaSnapshot(accountName, region string) (QuotaSnapshot, bool) {
	v, ok := quotaCache.Get(quotaCacheKey(accountName, region))
	if !ok {
		return QuotaSnapshot{}, false
	}
	snap, ok := v.(QuotaSnapshot)
	return snap, ok
}

func formatQuotaTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.Local().Format("2006-01-02 15:04:05")
}

func instanceCacheKey(acct auth.AWSAccount, region string) string {
	return strings.Join([]string{
		"inst",
		strings.ToLower(strings.TrimSpace(acct.Name)),
		normalizeRegion(region),
		strings.TrimSpace(acct.AK),
		strings.TrimSpace(acct.Proxy),
	}, "|")
}

func ec2InstanceCacheKey(acct auth.AWSAccount, region string) string {
	return strings.Join([]string{
		"ec2inst",
		strings.ToLower(strings.TrimSpace(acct.Name)),
		normalizeRegion(region),
		strings.TrimSpace(acct.AK),
		strings.TrimSpace(acct.Proxy),
	}, "|")
}

func resolveActiveAccount(s *session.Session, cfgMgr *auth.ConfigManager, requested string) (auth.AWSAccount, bool) {
	requested = strings.TrimSpace(requested)
	if requested == "" {
		requested = strings.TrimSpace(s.GetString(activeAccountSessionKey(), ""))
	}
	if requested == "" {
		requested = strings.TrimSpace(s.GetString(actionAccountSessionKey("create"), ""))
	}
	if requested == "" {
		requested = strings.TrimSpace(s.GetString(actionAccountSessionKey("manage"), ""))
	}
	if requested != "" {
		if acct, ok := cfgMgr.GetAccountByName(requested); ok {
			setActiveAccount(s, acct.Name)
			return acct, true
		}
		clearActiveAccount(s)
	}

	accounts := cfgMgr.GetAccounts()
	if len(accounts) == 0 {
		return auth.AWSAccount{}, false
	}

	return auth.AWSAccount{}, false
}

func loadStoredAccountQuota(acct auth.AWSAccount) (QuotaSnapshot, bool) {
	if strings.TrimSpace(acct.QuotaOn) == "" && strings.TrimSpace(acct.QuotaSpot) == "" {
		return QuotaSnapshot{}, false
	}
	snap := QuotaSnapshot{
		Region:      normalizeRegion(acct.QuotaRegion),
		OnDemand:    acct.QuotaOn,
		Spot:        acct.QuotaSpot,
		OnDemandMsg: acct.QuotaOnName,
		SpotMsg:     acct.QuotaSpName,
	}
	if acct.QuotaUpdatedAt > 0 {
		snap.UpdatedAt = time.Unix(acct.QuotaUpdatedAt, 0)
	}
	return snap, true
}

func applyQuotaSnapshotToCard(card *AWSAccountCard, snap QuotaSnapshot) {
	card.QuotaOn = snap.OnDemand
	card.QuotaSpot = snap.Spot
	card.QuotaOnName = snap.OnDemandMsg
	card.QuotaSpName = snap.SpotMsg
	card.QuotaUpdated = formatQuotaTime(snap.UpdatedAt)
	card.HasQuota = card.QuotaOn != "" || card.QuotaSpot != ""
}

func resolveAccountQuotaRegion(s *session.Session, acct auth.AWSAccount, fallback string) string {
	region := strings.TrimSpace(s.GetString(quotaRegionSessionKey(acct.Name), ""))
	if region == "" {
		region = strings.TrimSpace(acct.QuotaRegion)
	}
	if region == "" {
		region = strings.TrimSpace(acct.Region)
	}
	if region == "" {
		region = strings.TrimSpace(fallback)
	}
	region = normalizeRegion(region)
	if region == "" {
		region = "us-east-1"
	}
	return region
}

func buildAWSAccountCards(accounts []auth.AWSAccount, s *session.Session, fallbackRegion string, page, pageSize int) ([]AWSAccountCard, int, int, int) {
	total := len(accounts)
	if pageSize <= 0 {
		pageSize = awsAccountPageSize
	}
	totalPages := 1
	if total > 0 {
		totalPages = (total + pageSize - 1) / pageSize
	}
	if page < 1 {
		page = 1
	}
	if page > totalPages {
		page = totalPages
	}

	start := (page - 1) * pageSize
	if start > total {
		start = total
	}
	end := start + pageSize
	if end > total {
		end = total
	}

	cards := make([]AWSAccountCard, 0, end-start)
	for _, acct := range accounts[start:end] {
		region := resolveAccountQuotaRegion(s, acct, fallbackRegion)
		card := AWSAccountCard{
			AWSAccount:  acct,
			QuotaRegion: region,
		}
		if snap, ok := loadQuotaSnapshot(acct.Name, region); ok {
			applyQuotaSnapshotToCard(&card, snap)
		} else if snap, ok := loadStoredAccountQuota(acct); ok && (snap.Region == "" || snap.Region == region) {
			applyQuotaSnapshotToCard(&card, snap)
		}
		cards = append(cards, card)
	}

	return cards, page, totalPages, total
}

func genSessionID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func main() {
	port := mustEnvInt("PORT", 1234)

	cfgMgr, err := auth.NewConfigManager("config.json")
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	r := gin.New()
	r.Use(gin.Logger(), gin.Recovery())

	r.SetFuncMap(template.FuncMap{
		"regionLabel": regionLabel,
		"maskStr":     mask,
	})
	r.LoadHTMLGlob("templates/*.html")

	store := session.NewStore()

	// Session middleware
	r.Use(func(c *gin.Context) {
		sid, err := c.Cookie("sid")
		if err != nil || sid == "" {
			sid = genSessionID()
			c.SetCookie("sid", sid, 3600*24*7, "/", "", false, true)
		}
		s := store.GetOrCreate(sid)
		c.Set("sess", s)
		c.Set("sid", sid)
		c.Next()
	})

	// --- Login / Logout ---

	r.GET("/login", func(c *gin.Context) {
		cfg := cfgMgr.Get()
		c.HTML(http.StatusOK, "login", PageData{
			Title:    "AWS 工具站",
			Username: cfg.Username,
		})
	})

	r.POST("/login", func(c *gin.Context) {
		s := session.Must(c)
		username := strings.TrimSpace(c.PostForm("username"))
		password := strings.TrimSpace(c.PostForm("password"))

		cfg := cfgMgr.Get()
		if username == cfg.Username && cfgMgr.CheckPassword(password) {
			s.SetString("logged_in", "1")
			s.SetString("login_user", username)
			c.Redirect(http.StatusFound, "/")
			return
		}

		c.HTML(http.StatusOK, "login", PageData{
			Title:    "AWS 工具站",
			Username: username,
			Error:    "用户名或密码错误",
		})
	})

	r.POST("/logout", func(c *gin.Context) {
		s := session.Must(c)
		s.SetString("logged_in", "")
		s.SetString("login_user", "")
		clearActiveAccount(s)
		s.SetString("quota_account", "")
		s.SetString("rotated_ak", "")
		s.SetString("rotate_err_msg", "")
		c.Redirect(http.StatusFound, "/login")
	})

	// --- Auth middleware ---
	authRequired := func(c *gin.Context) {
		s := session.Must(c)
		if s.GetString("logged_in", "") != "1" {
			c.Redirect(http.StatusFound, "/login")
			c.Abort()
			return
		}
		c.Next()
	}

	protected := r.Group("/")
	protected.Use(authRequired)

	performQuotaTest := func(ctx context.Context, acct auth.AWSAccount, region string) (QuotaSnapshot, error) {
		sq, err := aws.NewServiceQuotasClient(ctx, region, acct.AK, acct.SK, acct.Proxy)
		if err != nil {
			return QuotaSnapshot{}, err
		}

		onVal, spotVal, onName, spotName, err := aws.TestVCPUQuotas(ctx, sq)
		if err != nil {
			return QuotaSnapshot{}, err
		}
		if strings.TrimSpace(onVal) == "" && strings.TrimSpace(spotVal) == "" {
			return QuotaSnapshot{}, fmt.Errorf("quota test returned empty results")
		}

		return QuotaSnapshot{
			Region:      region,
			OnDemand:    onVal,
			Spot:        spotVal,
			OnDemandMsg: onName,
			SpotMsg:     spotName,
			UpdatedAt:   time.Now(),
		}, nil
	}

	persistQuotaSnapshot := func(accountName string, snap QuotaSnapshot) {
		if err := cfgMgr.UpdateAccountQuota(accountName, auth.AWSQuotaSnapshot{
			Region:      snap.Region,
			OnDemand:    snap.OnDemand,
			Spot:        snap.Spot,
			OnDemandMsg: snap.OnDemandMsg,
			SpotMsg:     snap.SpotMsg,
			UpdatedAt:   snap.UpdatedAt.Unix(),
		}); err != nil {
			log.Printf("UpdateAccountQuota error for %s: %v", accountName, err)
		}
	}

	panelRedirect := func(tab string, values map[string]string) string {
		q := url.Values{}
		q.Set("tab", tab)
		for k, v := range values {
			if strings.TrimSpace(v) != "" {
				q.Set(k, v)
			}
		}
		return "/?" + q.Encode()
	}

	// --- Main page ---
	protected.GET("/", func(c *gin.Context) {
		s := session.Must(c)

		tab := c.Query("tab")
		if tab == "" {
			tab = s.GetString("tab", "awsaccount")
		}
		switch tab {
		case "newbie":
			tab = "awsaccount"
		case "staticip":
			tab = "awsaccount"
		}
		if tab != "settings" && tab != "awsaccount" && tab != "create" && tab != "manage" {
			tab = "awsaccount"
		}
		s.SetString("tab", tab)

		cfg := cfgMgr.Get()
		accounts := cfgMgr.GetAccounts()

		activeAcct, hasActiveAccount := resolveActiveAccount(s, cfgMgr, c.Query("account"))
		createAcct, hasCreateAccount := activeAcct, hasActiveAccount
		manageAcct, hasManageAccount := activeAcct, hasActiveAccount

		createService := strings.TrimSpace(c.Query("service"))
		if tab == "create" {
			if createService == "" {
				createService = strings.TrimSpace(s.GetString("create_service", "lightsail"))
			}
			if createService != "ec2" {
				createService = "lightsail"
			}
			s.SetString("create_service", createService)
		} else {
			createService = strings.TrimSpace(s.GetString("create_service", "lightsail"))
			if createService != "ec2" {
				createService = "lightsail"
			}
		}

		manageService := strings.TrimSpace(c.Query("service"))
		if tab == "manage" {
			if manageService == "" {
				manageService = strings.TrimSpace(s.GetString("manage_service", "lightsail"))
			}
			if manageService != "ec2" {
				manageService = "lightsail"
			}
			s.SetString("manage_service", manageService)
		} else {
			manageService = strings.TrimSpace(s.GetString("manage_service", "lightsail"))
			if manageService != "ec2" {
				manageService = "lightsail"
			}
		}

		createRegions := regionOptionsForService(createService)
		manageRegions := regionOptionsForService(manageService)

		region := normalizeRegion(c.Query("region"))
		if region == "" {
			switch tab {
			case "create":
				region = normalizeRegion(s.GetString("create_region", ""))
				if region == "" && hasCreateAccount {
					region = normalizeRegion(createAcct.Region)
				}
			case "manage":
				region = normalizeRegion(s.GetString("manage_region", ""))
				if region == "" && hasManageAccount {
					region = normalizeRegion(manageAcct.Region)
				}
			default:
				region = normalizeRegion(s.GetString("region", ""))
			}
		}
		if tab == "create" && !containsRegion(createRegions, region) {
			region = ""
			if hasCreateAccount && containsRegion(createRegions, normalizeRegion(createAcct.Region)) {
				region = normalizeRegion(createAcct.Region)
			}
		}
		if tab == "manage" && !containsRegion(manageRegions, region) {
			region = ""
			if hasManageAccount && containsRegion(manageRegions, normalizeRegion(manageAcct.Region)) {
				region = normalizeRegion(manageAcct.Region)
			}
		}
		if region == "" {
			region = "us-east-1"
		}
		s.SetString("region", region)
		if tab == "create" {
			s.SetString("create_region", region)
		}
		if tab == "manage" {
			s.SetString("manage_region", region)
		}

		awsPage := 1
		if tab == "awsaccount" {
			if rawPage := strings.TrimSpace(c.Query("page")); rawPage != "" {
				if parsed, err := strconv.Atoi(rawPage); err == nil && parsed > 0 {
					awsPage = parsed
				}
			} else if rawPage := strings.TrimSpace(s.GetString("awsaccount_page", "1")); rawPage != "" {
				if parsed, err := strconv.Atoi(rawPage); err == nil && parsed > 0 {
					awsPage = parsed
				}
			}
			s.SetString("awsaccount_page", strconv.Itoa(awsPage))
		}

		quotaAccount := s.GetString("quota_account", "")
		if quotaAccount == "" && len(accounts) > 0 {
			quotaAccount = accounts[0].Name
		}

		createRootPwd := strings.TrimSpace(s.GetString("create_root_pwd", ""))
		if createRootPwd == "" {
			createRootPwd = generateRandomPassword(16)
			s.SetString("create_root_pwd", createRootPwd)
		}

		createBundles := loadLightsailBundleOptions(c.Request.Context(), createAcct, region)
		createBundle := normalizeLightsailBundleForRegion(region, s.GetString("create_bundle", firstOptionID(createBundles)))
		if !containsOption(createBundles, createBundle) {
			createBundle = firstOptionID(createBundles)
		}
		if createBundle != "" {
			s.SetString("create_bundle", createBundle)
		}

		// Check if we have creds for quota
		hasQuotaCreds := false
		if quotaAccount != "" {
			if acct, ok := cfgMgr.GetAccountByName(quotaAccount); ok {
				hasQuotaCreds = acct.AK != "" && acct.SK != ""
			}
		}

		data := PageData{
			Title:            "AWS 工具站",
			Region:           region,
			Regions:          regionOptions,
			Tab:              tab,
			Accounts:         accounts,
			ActiveAccount:    strings.TrimSpace(activeAcct.Name),
			QuotaAccount:     quotaAccount,
			HasQuotaCreds:    hasQuotaCreds,
			HasCreateCreds:   hasCreateAccount && strings.TrimSpace(createAcct.AK) != "" && strings.TrimSpace(createAcct.SK) != "",
			HasManageCreds:   hasManageAccount && strings.TrimSpace(manageAcct.AK) != "" && strings.TrimSpace(manageAcct.SK) != "",
			CreateService:    createService,
			ManageService:    manageService,
			CreateEnableFW:   s.GetString("create_fw_all", "1") == "1",
			CreateIPType:     s.GetString("create_ip_type", "dualstack"),
			CreateBlueprint:  s.GetString("create_blueprint", "ubuntu_24_04"),
			CreateBundle:     createBundle,
			CreateRootPwd:    createRootPwd,
			CreateEC2AMI:     s.GetString("create_ec2_ami", "ubuntu-24.04"),
			CreateEC2Type:    s.GetString("create_ec2_type", "t3.micro"),
			CreateEC2Count:   clampInt(mustSessionInt(s.GetString("create_ec2_count", "1"), 1), 1, 10),
			CreateEC2IPv6:    s.GetString("create_ec2_ipv6", "0") == "1",
			CreateRegions:    createRegions,
			ManageRegions:    manageRegions,
			Blueprints:       blueprintOptions,
			Bundles:          createBundles,
			IPTypes:          ipTypeOptions,
			EC2AMIs:          ec2AMIOptions,
			EC2Types:         ec2InstanceTypeOptions,
			SpecialRegions:   specialRegionOptions,

			CfgUsername: cfg.Username,
		}

		switch c.Query("msg") {
		case "quota_ok":
			data.Flash.Success = "配额测试完成"
		case "quota_err":
			data.Flash.Error = "配额测试失败：未找到配额项或没有 Service Quotas 权限"
		case "account_ok":
			data.Flash.Success = "账户信息已更新"
		case "account_err":
			data.Flash.Error = "账户更新失败"
		case "aws_added":
			data.Flash.Success = "AWS 账户已添加或更新"
		case "aws_added_batch":
			addedCount := strings.TrimSpace(c.Query("count"))
			if addedCount == "" {
				addedCount = "0"
			}
			data.Flash.Success = "已批量添加 " + addedCount + " 个 AWS 账户"
		case "account_confirmed":
			data.Flash.Success = "面板已确认当前使用账户，创建和管理都会使用这个账号"
		case "account_selection_cleared":
			data.Flash.Info = "之前确认的 AWS 账户已不存在，面板已清空当前使用账户"
		case "create_need_confirmed_account":
			data.Flash.Warn = "请先在顶部确认要使用的 AWS 账户，再进行创建"
		case "manage_need_confirmed_account":
			data.Flash.Warn = "请先在顶部确认要使用的 AWS 账户，再进行管理"
		case "aws_deleted":
			data.Flash.Success = "AWS 账户已删除"
		case "aws_add_err":
			data.Flash.Error = "添加 AWS 账户失败，请检查名称或凭证内容"
		case "aws_add_incomplete":
			data.Flash.Error = "单个添加时必须同时填写 Access Key 和 Secret Key"
		case "aws_name_taken":
			data.Flash.Error = "这个 AWS 账户名称已经存在，请换一个名称"
		case "aws_add_parse_err":
			if msg := strings.TrimSpace(c.Query("err")); msg != "" {
				data.Flash.Error = "批量添加失败: " + msg
			} else {
				data.Flash.Error = "批量添加失败，未识别到有效的 Access Key / Secret Key"
			}
		case "aws_del_err":
			data.Flash.Error = "删除 AWS 账户失败"
		case "aws_rotated":
			data.Flash.Success = "密钥轮换成功，新 AK: " + s.GetString("rotated_ak", "")
		case "aws_rotate_err":
			data.Flash.Error = "密钥轮换失败: " + s.GetString("rotate_err_msg", "未知错误")
		case "create_need_account":
			data.Flash.Warn = "请先选择一个可用的 AWS 账户"
		case "create_need_pwd":
			data.Flash.Warn = "请填写实例的 Root 密码"
		case "create_need_ids":
			data.Flash.Warn = "请选择 Blueprint 和 Bundle"
		case "create_need_creds":
			data.Flash.Warn = "当前账户缺少可用的 AK/SK"
		case "create_need_type":
			data.Flash.Warn = "请选择 EC2 实例类型"
		case "created":
			data.Flash.Success = "实例创建请求已提交，请切到实例管理查看状态"
		case "create_failed":
			if msg := strings.TrimSpace(c.Query("err")); msg != "" {
				data.Flash.Error = "创建实例失败: " + msg
			} else {
				data.Flash.Error = "创建实例失败，请检查区域、配额、权限或代理配置"
			}
		case "manage_need_account":
			data.Flash.Warn = "请先选择一个可管理的 AWS 账户"
		case "manage_need_instance":
			data.Flash.Warn = "未指定实例名称"
		case "manage_need_creds":
			data.Flash.Warn = "当前账户缺少可用的 AK/SK"
		case "region_enable_requested":
			data.Flash.Success = "已提交特殊区域激活请求：" + regionLabel(strings.TrimSpace(c.Query("region_name")))
		case "region_enable_err":
			data.Flash.Error = "特殊区域激活失败"
		case "err_client":
			if msg := strings.TrimSpace(c.Query("err")); msg != "" {
				data.Flash.Error = "AWS 客户端初始化失败: " + msg
			} else {
				data.Flash.Error = "AWS 客户端初始化失败，请检查凭证、区域或代理"
			}
		case "reboot_ok":
			data.Flash.Success = "实例重启请求已提交"
		case "reboot_failed":
			if msg := strings.TrimSpace(c.Query("err")); msg != "" {
				data.Flash.Error = "实例重启失败: " + msg
			} else {
				data.Flash.Error = "实例重启失败"
			}
		case "start_ok":
			data.Flash.Success = "实例启动请求已提交"
		case "start_failed":
			if msg := strings.TrimSpace(c.Query("err")); msg != "" {
				data.Flash.Error = "实例启动失败: " + msg
			} else {
				data.Flash.Error = "实例启动失败"
			}
		case "stop_ok":
			data.Flash.Success = "实例停止请求已提交"
		case "stop_failed":
			if msg := strings.TrimSpace(c.Query("err")); msg != "" {
				data.Flash.Error = "实例停止失败: " + msg
			} else {
				data.Flash.Error = "实例停止失败"
			}
		case "openall_ok":
			data.Flash.Success = "实例全端口开放请求已提交"
		case "openall_failed":
			if msg := strings.TrimSpace(c.Query("err")); msg != "" {
				data.Flash.Error = "开放全端口失败: " + msg
			} else {
				data.Flash.Error = "开放全端口失败"
			}
		case "swapip_ok":
			data.Flash.Success = "更换静态 IP 请求已提交"
		case "swapip_failed":
			if msg := strings.TrimSpace(c.Query("err")); msg != "" {
				data.Flash.Error = "更换静态 IP 失败: " + msg
			} else {
				data.Flash.Error = "更换静态 IP 失败"
			}
		case "delete_ok":
			data.Flash.Success = "实例删除请求已提交"
		case "delete_failed":
			if msg := strings.TrimSpace(c.Query("err")); msg != "" {
				data.Flash.Error = "删除实例失败: " + msg
			} else {
				data.Flash.Error = "删除实例失败"
			}
		}

		if tab == "settings" || tab == "awsaccount" {
			cfg = cfgMgr.Get()
			data.Accounts = cfgMgr.GetAccounts()
			data.CfgUsername = cfg.Username
		}

		if tab == "awsaccount" {
			cards, page, totalPages, total := buildAWSAccountCards(data.Accounts, s, region, awsPage, awsAccountPageSize)
			data.AWSAccounts = cards
			data.AWSPage = page
			data.AWSPageSize = awsAccountPageSize
			data.AWSTotal = total
			data.AWSTotalPages = totalPages
			data.AWSHasPrev = page > 1
			data.AWSHasNext = page < totalPages
			if page > 1 {
				data.AWSPrevPage = page - 1
			}
			if page < totalPages {
				data.AWSNextPage = page + 1
			}
		}

		if tab == "create" && hasCreateAccount {
			if region == "us-east-1" && strings.TrimSpace(createAcct.Region) != "" && strings.TrimSpace(c.Query("region")) == "" && strings.TrimSpace(s.GetString("create_region", "")) == "" {
				candidate := normalizeRegion(createAcct.Region)
				if containsRegion(createRegions, candidate) {
					data.Region = candidate
					createBundles = loadLightsailBundleOptions(c.Request.Context(), createAcct, data.Region)
					createBundle = normalizeLightsailBundleForRegion(data.Region, createBundle)
					if !containsOption(createBundles, createBundle) {
						createBundle = firstOptionID(createBundles)
					}
					data.Bundles = createBundles
					data.CreateBundle = createBundle
				}
				if data.Region != "" {
					s.SetString("create_region", data.Region)
				}
				if data.CreateBundle != "" {
					s.SetString("create_bundle", data.CreateBundle)
				}
			}
		}

		if tab == "manage" && hasManageAccount {
			if data.HasManageCreds {
				if manageService == "ec2" {
					cacheKey := ec2InstanceCacheKey(manageAcct, data.Region)
					if cached, ok := instCache.Get(cacheKey); ok {
						if list, ok := cached.([]aws.EC2InstanceView); ok {
							data.EC2Instances = list
						}
					} else {
						cli, err := aws.NewEC2Client(c.Request.Context(), data.Region, manageAcct.AK, manageAcct.SK, manageAcct.Proxy)
						if err != nil {
							data.Flash.Error = "AWS 客户端初始化失败，请检查凭证、区域或代理"
						} else {
							list, err := aws.ListEC2InstancesStable(c.Request.Context(), cli)
							if err != nil {
								data.Flash.Error = "拉取 EC2 实例列表失败：" + err.Error()
							} else {
								data.EC2Instances = list
								instCache.Set(cacheKey, list, cache.DefaultExpiration)
							}
						}
					}
				} else {
					cacheKey := instanceCacheKey(manageAcct, data.Region)
					if cached, ok := instCache.Get(cacheKey); ok {
						if list, ok := cached.([]aws.InstanceView); ok {
							data.Instances = list
						}
					} else {
						cli, err := aws.NewLightsailClient(c.Request.Context(), data.Region, manageAcct.AK, manageAcct.SK, manageAcct.Proxy)
						if err != nil {
							data.Flash.Error = "AWS 客户端初始化失败，请检查凭证、区域或代理"
						} else {
							list, err := aws.ListInstancesStable(c.Request.Context(), cli)
							if err != nil {
								data.Flash.Error = "拉取实例列表失败：" + err.Error()
							} else {
								data.Instances = list
								instCache.Set(cacheKey, list, cache.DefaultExpiration)
							}
						}
					}
				}
			}
		}

		c.HTML(http.StatusOK, "layout", data)
	})

	protected.GET("/aws/proxy/check", func(c *gin.Context) {
		s := session.Must(c)
		accountName := strings.TrimSpace(c.Query("account"))
		if accountName == "" {
			accountName = s.GetString(activeAccountSessionKey(), "")
		}

		proxy := strings.TrimSpace(c.Query("proxy"))
		if proxy == "" && accountName != "" {
			if acct, ok := cfgMgr.GetAccountByName(accountName); ok {
				proxy = strings.TrimSpace(acct.Proxy)
			}
		}

		if proxy == "" {
			c.JSON(http.StatusOK, gin.H{"ok": false, "error": "当前账户未配置代理"})
			return
		}

		ip, asn, err := aws.CheckProxyExitIP(c.Request.Context(), proxy)
		if err != nil {
			c.JSON(http.StatusOK, gin.H{"ok": false, "error": err.Error()})
			return
		}

		c.JSON(http.StatusOK, gin.H{"ok": true, "ip": ip, "as": asn})
	})

	protected.GET("/settings/aws/regions", func(c *gin.Context) {
		accountName := strings.TrimSpace(c.Query("account"))
		acct, ok := cfgMgr.GetAccountByName(accountName)
		if !ok || strings.TrimSpace(acct.AK) == "" || strings.TrimSpace(acct.SK) == "" {
			c.JSON(http.StatusOK, gin.H{"ok": false, "error": "账户不存在或缺少 AK/SK"})
			return
		}

		cli, err := aws.NewAccountClient(c.Request.Context(), acct.AK, acct.SK, acct.Proxy)
		if err != nil {
			c.JSON(http.StatusOK, gin.H{"ok": false, "error": err.Error()})
			return
		}

		regions, err := aws.ListAccountRegions(c.Request.Context(), cli)
		if err != nil {
			c.JSON(http.StatusOK, gin.H{"ok": false, "error": err.Error()})
			return
		}

		statusMap := make(map[string]string, len(regions))
		for _, item := range regions {
			statusMap[strings.TrimSpace(item.RegionName)] = strings.TrimSpace(item.RegionOptStatus)
		}

		c.JSON(http.StatusOK, gin.H{
			"ok":      true,
			"regions": statusMap,
		})
	})

	protected.POST("/settings/aws/regions/enable", func(c *gin.Context) {
		s := session.Must(c)
		accountName := strings.TrimSpace(c.PostForm("acct_name"))
		regionName := normalizeRegion(strings.TrimSpace(c.PostForm("region_name")))
		page := 1
		if rawPage := strings.TrimSpace(c.PostForm("page")); rawPage != "" {
			if parsed, err := strconv.Atoi(rawPage); err == nil && parsed > 0 {
				page = parsed
			}
		}

		if accountName == "" || regionName == "" {
			c.Redirect(http.StatusFound, fmt.Sprintf("/?tab=awsaccount&page=%d&msg=region_enable_err", page))
			return
		}

		acct, ok := cfgMgr.GetAccountByName(accountName)
		if !ok || strings.TrimSpace(acct.AK) == "" || strings.TrimSpace(acct.SK) == "" {
			c.Redirect(http.StatusFound, fmt.Sprintf("/?tab=awsaccount&page=%d&msg=region_enable_err", page))
			return
		}

		cli, err := aws.NewAccountClient(c.Request.Context(), acct.AK, acct.SK, acct.Proxy)
		if err != nil {
			log.Printf("NewAccountClient error for %s: %v", accountName, err)
			c.Redirect(http.StatusFound, fmt.Sprintf("/?tab=awsaccount&page=%d&msg=region_enable_err", page))
			return
		}

		if err := aws.EnableAccountRegion(c.Request.Context(), cli, regionName); err != nil {
			log.Printf("EnableAccountRegion error for %s/%s: %v", accountName, regionName, err)
			s.SetString("awsaccount_page", strconv.Itoa(page))
			c.Redirect(http.StatusFound, fmt.Sprintf("/?tab=awsaccount&page=%d&msg=region_enable_err", page))
			return
		}

		s.SetString("awsaccount_page", strconv.Itoa(page))
		c.Redirect(http.StatusFound, fmt.Sprintf("/?tab=awsaccount&page=%d&msg=region_enable_requested&region_name=%s", page, url.QueryEscape(regionName)))
	})

	protected.POST("/aws/use", func(c *gin.Context) {
		s := session.Must(c)

		accountName := strings.TrimSpace(c.PostForm("account"))
		tab := strings.TrimSpace(c.PostForm("tab"))
		if tab != "manage" && tab != "create" {
			tab = "create"
		}

		service := strings.TrimSpace(c.PostForm("service"))
		if service != "ec2" {
			service = "lightsail"
		}

		missingAccountMsg := "create_need_account"
		if tab == "manage" {
			missingAccountMsg = "manage_need_account"
		}

		if accountName == "" {
			c.Redirect(http.StatusFound, panelRedirect(tab, map[string]string{
				"service": service,
				"msg":     missingAccountMsg,
			}))
			return
		}

		acct, ok := cfgMgr.GetAccountByName(accountName)
		if !ok {
			c.Redirect(http.StatusFound, panelRedirect(tab, map[string]string{
				"service": service,
				"msg":     missingAccountMsg,
			}))
			return
		}

		setActiveAccount(s, acct.Name)

		region := normalizeRegion(strings.TrimSpace(c.PostForm("region")))
		validRegions := regionOptionsForService(service)
		if !containsRegion(validRegions, region) {
			region = normalizeRegion(acct.Region)
		}
		if !containsRegion(validRegions, region) {
			region = "us-east-1"
		}

		s.SetString("region", region)
		s.SetString("create_region", region)
		s.SetString("manage_region", region)
		if tab == "create" {
			s.SetString("create_service", service)
		} else {
			s.SetString("manage_service", service)
		}

		c.Redirect(http.StatusFound, panelRedirect(tab, map[string]string{
			"service": service,
			"region":  region,
			"msg":     "account_confirmed",
		}))
	})

	protected.POST("/aws/create", func(c *gin.Context) {
		s := session.Must(c)

		accountName := strings.TrimSpace(c.PostForm("account"))
		if accountName == "" {
			c.Redirect(http.StatusFound, panelRedirect("create", map[string]string{"msg": "create_need_confirmed_account"}))
			return
		}

		acct, ok := cfgMgr.GetAccountByName(accountName)
		if !ok || strings.TrimSpace(acct.AK) == "" || strings.TrimSpace(acct.SK) == "" {
			c.Redirect(http.StatusFound, panelRedirect("create", map[string]string{
				"account": accountName,
				"service": strings.TrimSpace(c.PostForm("service")),
				"msg":     "create_need_creds",
			}))
			return
		}
		setActiveAccount(s, acct.Name)

		service := strings.TrimSpace(c.PostForm("service"))
		if service != "ec2" {
			service = "lightsail"
		}
		s.SetString("create_service", service)
		s.SetString("manage_service", service)

		region := normalizeRegion(strings.TrimSpace(c.PostForm("region")))
		if region == "" {
			region = normalizeRegion(acct.Region)
		}
		if region == "" {
			region = "us-east-1"
		}

		validRegions := regionOptionsForService(service)
		if !containsRegion(validRegions, region) {
			region = "us-east-1"
		}
		s.SetString("region", region)
		s.SetString("create_region", region)
		s.SetString("manage_region", region)

		az := strings.TrimSpace(c.PostForm("az"))
		if az == "" || (az != "a" && az != "b" && az != "c") {
			az = "a"
		}

		rootPwd := strings.TrimSpace(c.PostForm("root_pwd"))
		if rootPwd != "" {
			s.SetString("create_root_pwd", rootPwd)
		} else {
			s.SetString("create_root_pwd", "")
		}

		if service == "ec2" {
			ami := strings.TrimSpace(c.PostForm("ec2_ami"))
			if ami == "" {
				ami = "ubuntu-24.04"
			}
			instanceType := strings.TrimSpace(c.PostForm("ec2_type"))
			if instanceType == "" {
				c.Redirect(http.StatusFound, panelRedirect("create", map[string]string{
					"account": accountName,
					"service": service,
					"region":  region,
					"msg":     "create_need_type",
				}))
				return
			}
			count := clampInt(mustSessionInt(strings.TrimSpace(c.PostForm("ec2_count")), 1), 1, 10)
			enableIPv6 := strings.TrimSpace(c.PostForm("ec2_ipv6")) == "1"

			s.SetString("create_ec2_ami", ami)
			s.SetString("create_ec2_type", instanceType)
			s.SetString("create_ec2_count", strconv.Itoa(count))
			if enableIPv6 {
				s.SetString("create_ec2_ipv6", "1")
			} else {
				s.SetString("create_ec2_ipv6", "0")
			}

			cli, err := aws.NewEC2Client(c.Request.Context(), region, acct.AK, acct.SK, acct.Proxy)
			if err != nil {
				c.Redirect(http.StatusFound, panelRedirect("create", map[string]string{
					"account": accountName,
					"service": service,
					"region":  region,
					"msg":     "err_client",
					"err":     err.Error(),
				}))
				return
			}

			amiID, err := aws.ResolveEC2AMI(c.Request.Context(), cli, ami)
			if err != nil {
				log.Printf("ResolveEC2AMI error for %s: %v", accountName, err)
				c.Redirect(http.StatusFound, panelRedirect("create", map[string]string{
					"account": accountName,
					"service": service,
					"region":  region,
					"msg":     "create_failed",
					"err":     err.Error(),
				}))
				return
			}

			userData := ""
			if rootPwd != "" {
				userData = aws.BuildRootPasswordUserData(rootPwd)
			}

			err = aws.CreateEC2InstanceStable(c.Request.Context(), cli, aws.CreateEC2InstanceInput{
				Name:         "ec2-" + strconv.FormatInt(time.Now().Unix(), 10),
				AMI:          amiID,
				InstanceType: instanceType,
				Count:        int32(count),
				UserData:     userData,
				EnableIPv6:   enableIPv6,
			})
			if err != nil {
				log.Printf("CreateEC2Instance error for %s: %v", accountName, err)
				c.Redirect(http.StatusFound, panelRedirect("create", map[string]string{
					"account": accountName,
					"service": service,
					"region":  region,
					"msg":     "create_failed",
					"err":     err.Error(),
				}))
				return
			}

			instCache.Delete(ec2InstanceCacheKey(acct, region))
			s.SetString("create_root_pwd", generateRandomPassword(16))
			c.Redirect(http.StatusFound, panelRedirect("manage", map[string]string{
				"account": accountName,
				"service": service,
				"region":  region,
				"msg":     "created",
			}))
			return
		}

		ipType := strings.TrimSpace(c.PostForm("ip_type"))
		if ipType == "" {
			ipType = "dualstack"
		}
		s.SetString("create_ip_type", ipType)

		enableFW := c.PostForm("enable_fw") == "1"
		if enableFW {
			s.SetString("create_fw_all", "1")
		} else {
			s.SetString("create_fw_all", "0")
		}

		blueprint := strings.TrimSpace(c.PostForm("blueprint_id"))
		createBundles := loadLightsailBundleOptions(c.Request.Context(), acct, region)
		bundle := normalizeLightsailBundleForRegion(region, c.PostForm("bundle_id"))
		if !containsOption(createBundles, bundle) {
			bundle = firstOptionID(createBundles)
		}

		if blueprint != "" {
			s.SetString("create_blueprint", blueprint)
		}
		if bundle != "" {
			s.SetString("create_bundle", bundle)
		}

		if rootPwd == "" {
			c.Redirect(http.StatusFound, panelRedirect("create", map[string]string{
				"account": accountName,
				"service": service,
				"region":  region,
				"msg":     "create_need_pwd",
			}))
			return
		}
		if blueprint == "" || bundle == "" {
			c.Redirect(http.StatusFound, panelRedirect("create", map[string]string{
				"account": accountName,
				"service": service,
				"region":  region,
				"msg":     "create_need_ids",
			}))
			return
		}

		instanceName := "vps-" + strconv.FormatInt(time.Now().Unix(), 10)
		bundleToUse := bundle
		if ipType == "ipv6" {
			if mapped, ok := ipv6BundleMap[bundle]; ok {
				bundleToUse = mapped
			}
		}

		cli, err := aws.NewLightsailClient(c.Request.Context(), region, acct.AK, acct.SK, acct.Proxy)
		if err != nil {
			c.Redirect(http.StatusFound, panelRedirect("create", map[string]string{
				"account": accountName,
				"service": service,
				"region":  region,
				"msg":     "err_client",
				"err":     err.Error(),
			}))
			return
		}

		err = aws.CreateInstanceStable(c.Request.Context(), cli, aws.CreateInstanceInput{
			InstanceName:     instanceName,
			AvailabilityZone: region + az,
			BlueprintID:      blueprint,
			BundleID:         bundleToUse,
			UserData:         aws.BuildRootPasswordUserData(rootPwd),
			IPAddressType:    ipType,
			EnableFWAll:      enableFW,
		})
		if err != nil {
			log.Printf("CreateInstance error for %s: %v", accountName, err)
			c.Redirect(http.StatusFound, panelRedirect("create", map[string]string{
				"account": accountName,
				"service": service,
				"region":  region,
				"msg":     "create_failed",
				"err":     err.Error(),
			}))
			return
		}

		instCache.Delete(instanceCacheKey(acct, region))
		s.SetString("create_root_pwd", generateRandomPassword(16))
		c.Redirect(http.StatusFound, panelRedirect("manage", map[string]string{
			"account": accountName,
			"service": service,
			"region":  region,
			"msg":     "created",
		}))
	})

	doManageAction := func(action string, fn func(cli aws.LightsailAPI, instanceName string, ctx *gin.Context) error) gin.HandlerFunc {
		return func(c *gin.Context) {
			s := session.Must(c)
			accountName := strings.TrimSpace(c.PostForm("account"))
			if accountName == "" {
				accountName = s.GetString(actionAccountSessionKey("manage"), "")
			}
			if accountName == "" {
				c.Redirect(http.StatusFound, panelRedirect("manage", map[string]string{"msg": "manage_need_confirmed_account", "service": "lightsail"}))
				return
			}

			acct, ok := cfgMgr.GetAccountByName(accountName)
			if !ok || strings.TrimSpace(acct.AK) == "" || strings.TrimSpace(acct.SK) == "" {
				c.Redirect(http.StatusFound, panelRedirect("manage", map[string]string{
					"account": accountName,
					"service": "lightsail",
					"msg":     "manage_need_creds",
				}))
				return
			}

			region := normalizeRegion(strings.TrimSpace(c.PostForm("region")))
			if region == "" {
				region = normalizeRegion(s.GetString("manage_region", ""))
			}
			if region == "" {
				region = normalizeRegion(acct.Region)
			}
			if region == "" {
				region = "us-east-1"
			}
			setActiveAccount(s, acct.Name)
			s.SetString("manage_service", "lightsail")
			s.SetString("region", region)
			s.SetString("manage_region", region)

			instanceName := strings.TrimSpace(c.PostForm("instance"))
			if instanceName == "" {
				c.Redirect(http.StatusFound, panelRedirect("manage", map[string]string{
					"account": accountName,
					"service": "lightsail",
					"region":  region,
					"msg":     "manage_need_instance",
				}))
				return
			}

			cli, err := aws.NewLightsailClient(c.Request.Context(), region, acct.AK, acct.SK, acct.Proxy)
			if err != nil {
				c.Redirect(http.StatusFound, panelRedirect("manage", map[string]string{
					"account": accountName,
					"service": "lightsail",
					"region":  region,
					"msg":     "err_client",
					"err":     err.Error(),
				}))
				return
			}

			if err := fn(cli, instanceName, c); err != nil {
				log.Printf("%s error for %s/%s: %v", action, accountName, instanceName, err)
				c.Redirect(http.StatusFound, panelRedirect("manage", map[string]string{
					"account": accountName,
					"service": "lightsail",
					"region":  region,
					"msg":     action + "_failed",
					"err":     err.Error(),
				}))
				return
			}

			instCache.Delete(instanceCacheKey(acct, region))
			c.Redirect(http.StatusFound, panelRedirect("manage", map[string]string{
				"account": accountName,
				"service": "lightsail",
				"region":  region,
				"msg":     action + "_ok",
			}))
		}
	}

	doManageActionEC2 := func(action string, fn func(cli *ec2.Client, instanceID string, ctx *gin.Context) error) gin.HandlerFunc {
		return func(c *gin.Context) {
			s := session.Must(c)
			accountName := strings.TrimSpace(c.PostForm("account"))
			if accountName == "" {
				accountName = s.GetString(actionAccountSessionKey("manage"), "")
			}
			if accountName == "" {
				c.Redirect(http.StatusFound, panelRedirect("manage", map[string]string{"msg": "manage_need_confirmed_account", "service": "ec2"}))
				return
			}

			acct, ok := cfgMgr.GetAccountByName(accountName)
			if !ok || strings.TrimSpace(acct.AK) == "" || strings.TrimSpace(acct.SK) == "" {
				c.Redirect(http.StatusFound, panelRedirect("manage", map[string]string{
					"account": accountName,
					"service": "ec2",
					"msg":     "manage_need_creds",
				}))
				return
			}

			region := normalizeRegion(strings.TrimSpace(c.PostForm("region")))
			if region == "" {
				region = normalizeRegion(s.GetString("manage_region", ""))
			}
			if region == "" {
				region = normalizeRegion(acct.Region)
			}
			if region == "" || !containsRegion(ec2RegionOptions, region) {
				region = "us-east-1"
			}
			setActiveAccount(s, acct.Name)
			s.SetString("manage_service", "ec2")
			s.SetString("region", region)
			s.SetString("manage_region", region)

			instanceID := strings.TrimSpace(c.PostForm("instance"))
			if instanceID == "" {
				c.Redirect(http.StatusFound, panelRedirect("manage", map[string]string{
					"account": accountName,
					"service": "ec2",
					"region":  region,
					"msg":     "manage_need_instance",
				}))
				return
			}

			cli, err := aws.NewEC2Client(c.Request.Context(), region, acct.AK, acct.SK, acct.Proxy)
			if err != nil {
				c.Redirect(http.StatusFound, panelRedirect("manage", map[string]string{
					"account": accountName,
					"service": "ec2",
					"region":  region,
					"msg":     "err_client",
					"err":     err.Error(),
				}))
				return
			}

			if err := fn(cli, instanceID, c); err != nil {
				log.Printf("%s EC2 error for %s/%s: %v", action, accountName, instanceID, err)
				c.Redirect(http.StatusFound, panelRedirect("manage", map[string]string{
					"account": accountName,
					"service": "ec2",
					"region":  region,
					"msg":     action + "_failed",
					"err":     err.Error(),
				}))
				return
			}

			instCache.Delete(ec2InstanceCacheKey(acct, region))
			c.Redirect(http.StatusFound, panelRedirect("manage", map[string]string{
				"account": accountName,
				"service": "ec2",
				"region":  region,
				"msg":     action + "_ok",
			}))
		}
	}

	protected.POST("/aws/refresh", func(c *gin.Context) {
		s := session.Must(c)
		accountName := strings.TrimSpace(c.PostForm("account"))
		if accountName == "" {
			accountName = s.GetString(actionAccountSessionKey("manage"), "")
		}
		if accountName == "" {
			c.Redirect(http.StatusFound, panelRedirect("manage", map[string]string{"msg": "manage_need_confirmed_account"}))
			return
		}

		acct, ok := cfgMgr.GetAccountByName(accountName)
		if !ok {
			c.Redirect(http.StatusFound, panelRedirect("manage", map[string]string{"msg": "manage_need_confirmed_account"}))
			return
		}

		service := strings.TrimSpace(c.PostForm("service"))
		if service != "ec2" {
			service = "lightsail"
		}
		s.SetString("manage_service", service)

		region := normalizeRegion(strings.TrimSpace(c.PostForm("region")))
		if region == "" {
			region = normalizeRegion(s.GetString("manage_region", ""))
		}
		if region == "" {
			region = normalizeRegion(acct.Region)
		}
		if region == "" || !containsRegion(regionOptionsForService(service), region) {
			region = "us-east-1"
		}

		setActiveAccount(s, acct.Name)
		s.SetString("manage_region", region)
		if service == "ec2" {
			instCache.Delete(ec2InstanceCacheKey(acct, region))
		} else {
			instCache.Delete(instanceCacheKey(acct, region))
		}
		c.Redirect(http.StatusFound, panelRedirect("manage", map[string]string{
			"account": accountName,
			"service": service,
			"region":  region,
		}))
	})

	protected.POST("/aws/reboot", doManageAction("reboot", func(cli aws.LightsailAPI, instanceName string, ctx *gin.Context) error {
		return aws.RebootInstance(ctx.Request.Context(), cli, instanceName)
	}))

	protected.POST("/aws/openall", doManageAction("openall", func(cli aws.LightsailAPI, instanceName string, ctx *gin.Context) error {
		return aws.OpenAllPorts(ctx.Request.Context(), cli, instanceName)
	}))

	protected.POST("/aws/swapip", doManageAction("swapip", func(cli aws.LightsailAPI, instanceName string, ctx *gin.Context) error {
		return aws.SwapStaticIPForInstanceStable(ctx.Request.Context(), cli, instanceName)
	}))

	protected.POST("/aws/delete", doManageAction("delete", func(cli aws.LightsailAPI, instanceName string, ctx *gin.Context) error {
		return aws.DeleteInstanceWithStaticIPCleanupStable(ctx.Request.Context(), cli, instanceName)
	}))

	protected.POST("/aws/ec2/start", doManageActionEC2("start", func(cli *ec2.Client, instanceID string, ctx *gin.Context) error {
		return aws.StartEC2Instance(ctx.Request.Context(), cli, instanceID)
	}))

	protected.POST("/aws/ec2/stop", doManageActionEC2("stop", func(cli *ec2.Client, instanceID string, ctx *gin.Context) error {
		return aws.StopEC2Instance(ctx.Request.Context(), cli, instanceID)
	}))

	protected.POST("/aws/ec2/reboot", doManageActionEC2("reboot", func(cli *ec2.Client, instanceID string, ctx *gin.Context) error {
		return aws.RebootEC2Instance(ctx.Request.Context(), cli, instanceID)
	}))

	protected.POST("/aws/ec2/openall", doManageActionEC2("openall", func(cli *ec2.Client, instanceID string, ctx *gin.Context) error {
		return aws.OpenAllEC2Ports(ctx.Request.Context(), cli, instanceID)
	}))

	protected.POST("/aws/ec2/terminate", doManageActionEC2("delete", func(cli *ec2.Client, instanceID string, ctx *gin.Context) error {
		return aws.TerminateEC2Instance(ctx.Request.Context(), cli, instanceID)
	}))

	// --- Quota test ---
	protected.POST("/aws/quota", func(c *gin.Context) {
		s := session.Must(c)

		// Which account to use for quota
		acctName := strings.TrimSpace(c.PostForm("quota_account"))
		if acctName == "" {
			acctName = s.GetString("quota_account", "")
		}
		s.SetString("quota_account", acctName)

		acct, ok := cfgMgr.GetAccountByName(acctName)
		if !ok || acct.AK == "" || acct.SK == "" {
			c.Redirect(http.StatusFound, "/?tab=awsaccount&msg=quota_err")
			return
		}

		region := normalizeRegion(strings.TrimSpace(c.PostForm("quota_region")))
		if region == "" {
			region = normalizeRegion(s.GetString("region", "us-east-1"))
		}
		s.SetString("quota_region", region)
		s.SetString(quotaRegionSessionKey(acctName), region)

		snap, err := performQuotaTest(c.Request.Context(), acct, region)
		if err != nil {
			s.SetString("quota_on", "")
			s.SetString("quota_spot", "")
			s.SetString("quota_on_name", "")
			s.SetString("quota_sp_name", "")
			c.Redirect(http.StatusFound, "/?tab=awsaccount&msg=quota_err")
			return
		}

		storeQuotaSnapshot(acctName, region, snap)
		persistQuotaSnapshot(acctName, snap)
		s.SetString("quota_on", snap.OnDemand)
		s.SetString("quota_spot", snap.Spot)
		s.SetString("quota_on_name", snap.OnDemandMsg)
		s.SetString("quota_sp_name", snap.SpotMsg)

		c.Redirect(http.StatusFound, "/?tab=awsaccount&msg=quota_ok")
	})

	protected.POST("/settings/aws/quota", func(c *gin.Context) {
		s := session.Must(c)

		acctName := strings.TrimSpace(c.PostForm("acct_name"))
		page := 1
		if rawPage := strings.TrimSpace(c.PostForm("page")); rawPage != "" {
			if parsed, err := strconv.Atoi(rawPage); err == nil && parsed > 0 {
				page = parsed
			}
		}
		s.SetString("awsaccount_page", strconv.Itoa(page))

		if acctName == "" {
			c.Redirect(http.StatusFound, fmt.Sprintf("/?tab=awsaccount&page=%d&msg=quota_err", page))
			return
		}

		acct, ok := cfgMgr.GetAccountByName(acctName)
		if !ok || acct.AK == "" || acct.SK == "" {
			c.Redirect(http.StatusFound, fmt.Sprintf("/?tab=awsaccount&page=%d&msg=quota_err", page))
			return
		}

		region := normalizeRegion(strings.TrimSpace(c.PostForm("quota_region")))
		if region == "" {
			region = resolveAccountQuotaRegion(s, acct, s.GetString("region", "us-east-1"))
		}
		s.SetString(quotaRegionSessionKey(acctName), region)

		snap, err := performQuotaTest(c.Request.Context(), acct, region)
		if err != nil {
			c.Redirect(http.StatusFound, fmt.Sprintf("/?tab=awsaccount&page=%d&msg=quota_err", page))
			return
		}

		storeQuotaSnapshot(acctName, region, snap)
		persistQuotaSnapshot(acctName, snap)
		c.Redirect(http.StatusFound, fmt.Sprintf("/?tab=awsaccount&page=%d&msg=quota_ok", page))
	})

	// --- Settings routes ---
	protected.POST("/settings/account", func(c *gin.Context) {
		username := strings.TrimSpace(c.PostForm("username"))
		password := strings.TrimSpace(c.PostForm("password"))
		if username == "" && password == "" {
			c.Redirect(http.StatusFound, "/?tab=settings&msg=account_err")
			return
		}
		if err := cfgMgr.SetAccount(username, password); err != nil {
			log.Printf("SetAccount error: %v", err)
			c.Redirect(http.StatusFound, "/?tab=settings&msg=account_err")
			return
		}
		c.Redirect(http.StatusFound, "/?tab=settings&msg=account_ok")
	})

	// --- Multi-account AWS routes ---
	protected.POST("/settings/aws/add", func(c *gin.Context) {
		s := session.Must(c)
		addMode := strings.TrimSpace(c.PostForm("add_mode"))
		name := strings.TrimSpace(c.PostForm("acct_name"))
		bulkRaw := strings.TrimSpace(c.PostForm("acct_bulk"))
		oldName := strings.TrimSpace(c.PostForm("old_acct_name"))
		page := 1
		if rawPage := strings.TrimSpace(c.PostForm("page")); rawPage != "" {
			if parsed, err := strconv.Atoi(rawPage); err == nil && parsed > 0 {
				page = parsed
			}
		} else if rawPage := strings.TrimSpace(s.GetString("awsaccount_page", "1")); rawPage != "" {
			if parsed, err := strconv.Atoi(rawPage); err == nil && parsed > 0 {
				page = parsed
			}
		}
		s.SetString("awsaccount_page", strconv.Itoa(page))

		defaultRegion := normalizeRegion(strings.TrimSpace(c.PostForm("acct_region")))
		if defaultRegion == "" {
			defaultRegion = "us-east-1"
		}
		defaultProxy := strings.TrimSpace(c.PostForm("acct_proxy"))

		useBulk := oldName == "" && addMode == "bulk"
		if oldName == "" && addMode == "" && bulkRaw != "" {
			useBulk = true
		}

		if useBulk {
			if bulkRaw == "" {
				c.Redirect(http.StatusFound, fmt.Sprintf("/?tab=awsaccount&page=%d&msg=aws_add_parse_err&err=%s", page, url.QueryEscape("请先粘贴要批量添加的账号内容")))
				return
			}
			accounts := parseBulkAWSAccounts(bulkRaw, defaultProxy, defaultRegion, cfgMgr.GetAccounts())
			if len(accounts) == 0 {
				c.Redirect(http.StatusFound, fmt.Sprintf("/?tab=awsaccount&page=%d&msg=aws_add_parse_err&err=%s", page, url.QueryEscape("未识别到有效的 Access Key / Secret Key")))
				return
			}
			for _, acct := range accounts {
				if err := cfgMgr.AddAccount(acct); err != nil {
					log.Printf("AddAccount(batch) error: %v", err)
					c.Redirect(http.StatusFound, fmt.Sprintf("/?tab=awsaccount&page=%d&msg=aws_add_parse_err&err=%s", page, url.QueryEscape("保存批量账号时失败")))
					return
				}
			}
			c.Redirect(http.StatusFound, fmt.Sprintf("/?tab=awsaccount&page=%d&msg=aws_added_batch&count=%d", page, len(accounts)))
			return
		}

		if oldName == "" && name == "" && (strings.TrimSpace(c.PostForm("acct_ak")) != "" || strings.TrimSpace(c.PostForm("acct_sk")) != "") {
			used := make(map[string]struct{}, len(cfgMgr.GetAccounts()))
			for _, acct := range cfgMgr.GetAccounts() {
				used[strings.ToLower(strings.TrimSpace(acct.Name))] = struct{}{}
			}
			name = ensureUniqueAccountName(generateRandomAccountName(), used)
		}

		singleAK := strings.TrimSpace(c.PostForm("acct_ak"))
		singleSK := strings.TrimSpace(c.PostForm("acct_sk"))
		if addMode == "single" && oldName == "" {
			if singleAK == "" && singleSK == "" {
				c.Redirect(http.StatusFound, fmt.Sprintf("/?tab=awsaccount&page=%d&msg=aws_add_err", page))
				return
			}
			if singleAK == "" || singleSK == "" {
				c.Redirect(http.StatusFound, fmt.Sprintf("/?tab=awsaccount&page=%d&msg=aws_add_incomplete", page))
				return
			}
		}

		if name == "" {
			c.Redirect(http.StatusFound, fmt.Sprintf("/?tab=awsaccount&page=%d&msg=aws_add_err", page))
			return
		}
		acct := auth.AWSAccount{
			Name:   name,
			AK:     singleAK,
			SK:     singleSK,
			Proxy:  defaultProxy,
			Region: defaultRegion,
		}
		if oldName != "" && oldName != name {
			if _, exists := cfgMgr.GetAccountByName(name); exists {
				c.Redirect(http.StatusFound, fmt.Sprintf("/?tab=awsaccount&page=%d&msg=aws_name_taken", page))
				return
			}
			// Renaming: update old account with new data including new name
			if err := cfgMgr.UpdateAccount(oldName, acct); err != nil {
				log.Printf("UpdateAccount(rename) error: %v", err)
				c.Redirect(http.StatusFound, fmt.Sprintf("/?tab=awsaccount&page=%d&msg=aws_add_err", page))
				return
			}
			syncSessionAccountRename(s, oldName, name)
		} else {
			if err := cfgMgr.AddAccount(acct); err != nil {
				log.Printf("AddAccount error: %v", err)
				c.Redirect(http.StatusFound, fmt.Sprintf("/?tab=awsaccount&page=%d&msg=aws_add_err", page))
				return
			}
		}
		c.Redirect(http.StatusFound, fmt.Sprintf("/?tab=awsaccount&page=%d&msg=aws_added", page))
	})

	protected.POST("/settings/aws/delete", func(c *gin.Context) {
		s := session.Must(c)
		name := strings.TrimSpace(c.PostForm("acct_name"))
		page := 1
		if rawPage := strings.TrimSpace(c.PostForm("page")); rawPage != "" {
			if parsed, err := strconv.Atoi(rawPage); err == nil && parsed > 0 {
				page = parsed
			}
		} else if rawPage := strings.TrimSpace(s.GetString("awsaccount_page", "1")); rawPage != "" {
			if parsed, err := strconv.Atoi(rawPage); err == nil && parsed > 0 {
				page = parsed
			}
		}
		s.SetString("awsaccount_page", strconv.Itoa(page))
		if name == "" {
			c.Redirect(http.StatusFound, fmt.Sprintf("/?tab=awsaccount&page=%d&msg=aws_del_err", page))
			return
		}
		if err := cfgMgr.RemoveAccount(name); err != nil {
			log.Printf("RemoveAccount error: %v", err)
			c.Redirect(http.StatusFound, fmt.Sprintf("/?tab=awsaccount&page=%d&msg=aws_del_err", page))
			return
		}
		syncSessionAccountRemoval(s, cfgMgr, name)
		c.Redirect(http.StatusFound, fmt.Sprintf("/?tab=awsaccount&page=%d&msg=aws_deleted", page))
	})

	// --- Rotate access keys ---
	protected.POST("/settings/aws/rotate", func(c *gin.Context) {
		s := session.Must(c)
		name := strings.TrimSpace(c.PostForm("acct_name"))
		page := 1
		if rawPage := strings.TrimSpace(c.PostForm("page")); rawPage != "" {
			if parsed, err := strconv.Atoi(rawPage); err == nil && parsed > 0 {
				page = parsed
			}
		} else if rawPage := strings.TrimSpace(s.GetString("awsaccount_page", "1")); rawPage != "" {
			if parsed, err := strconv.Atoi(rawPage); err == nil && parsed > 0 {
				page = parsed
			}
		}
		s.SetString("awsaccount_page", strconv.Itoa(page))
		if name == "" {
			s.SetString("rotate_err_msg", "账户名称不能为空")
			c.Redirect(http.StatusFound, fmt.Sprintf("/?tab=awsaccount&page=%d&msg=aws_rotate_err", page))
			return
		}
		acct, ok := cfgMgr.GetAccountByName(name)
		if !ok || acct.AK == "" || acct.SK == "" {
			s.SetString("rotate_err_msg", "账户不存在或缺少凭证")
			c.Redirect(http.StatusFound, fmt.Sprintf("/?tab=awsaccount&page=%d&msg=aws_rotate_err", page))
			return
		}

		iamCli, err := aws.NewIAMClient(c.Request.Context(), acct.AK, acct.SK, acct.Proxy)
		if err != nil {
			log.Printf("NewIAMClient error: %v", err)
			s.SetString("rotate_err_msg", err.Error())
			c.Redirect(http.StatusFound, fmt.Sprintf("/?tab=awsaccount&page=%d&msg=aws_rotate_err", page))
			return
		}

		newAK, newSK, err := aws.RotateAccessKeys(c.Request.Context(), iamCli)
		if err != nil {
			log.Printf("RotateAccessKeys error: %v", err)
			s.SetString("rotate_err_msg", err.Error())
			c.Redirect(http.StatusFound, fmt.Sprintf("/?tab=awsaccount&page=%d&msg=aws_rotate_err", page))
			return
		}

		if err := cfgMgr.UpdateAccountKeys(name, newAK, newSK); err != nil {
			log.Printf("UpdateAccountKeys error: %v", err)
			s.SetString("rotate_err_msg", "密钥已在 AWS 端更新，但本地保存失败: "+err.Error())
			c.Redirect(http.StatusFound, fmt.Sprintf("/?tab=awsaccount&page=%d&msg=aws_rotate_err", page))
			return
		}

		s.SetString("rotated_ak", newAK)
		c.Redirect(http.StatusFound, fmt.Sprintf("/?tab=awsaccount&page=%d&msg=aws_rotated", page))
	})

	// --- Newbie Task routes ---
	protected.POST("/aws/newbie/run", func(c *gin.Context) {
		acctName := strings.TrimSpace(c.PostForm("account"))
		if acctName == "" {
			c.JSON(200, gin.H{"error": "未选择账户"})
			return
		}

		acct, ok := cfgMgr.GetAccountByName(acctName)
		if !ok || acct.AK == "" || acct.SK == "" {
			c.JSON(200, gin.H{"error": "该账户无效或缺少凭证（AK/SK）"})
			return
		}

		newbieTaskMu.Lock()
		defer newbieTaskMu.Unlock()

		if activeNewbieTask != nil {
			select {
			case <-activeNewbieTask.LogsChan:
				// Channel closed, task is done
				activeNewbieTask = nil
			default:
				c.JSON(200, gin.H{"error": "当前有另一个任务正在执行，请稍后再试"})
				return
			}
		}

		task, err := aws.NewNewbieTaskEngine(context.Background(), acct.AK, acct.SK, acct.Proxy)
		if err != nil {
			c.JSON(200, gin.H{"error": "初始化失败: " + err.Error()})
			return
		}

		activeNewbieTask = task
		go func() {
			task.RunAll()
		}()

		c.JSON(200, gin.H{"message": "started"})
	})

	protected.GET("/aws/newbie/stream", func(c *gin.Context) {
		c.Writer.Header().Set("Content-Type", "text/event-stream")
		c.Writer.Header().Set("Cache-Control", "no-cache")
		c.Writer.Header().Set("Connection", "keep-alive")

		newbieTaskMu.Lock()
		task := activeNewbieTask
		newbieTaskMu.Unlock()

		if task == nil {
			c.SSEvent("message", "没有正在运行的任务。")
			c.Writer.Flush()
			return
		}

		ctx := c.Request.Context()
		for {
			select {
			case <-ctx.Done():
				return
			case msg, ok := <-task.LogsChan:
				if !ok {
					c.SSEvent("message", "执行完毕，连接断开。")
					c.Writer.Flush()
					return
				}
				c.SSEvent("message", msg)
				c.Writer.Flush()
			}
		}
	})

	_ = r.Run(":" + strconv.Itoa(port))
}

func mask(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	if len(s) <= 6 {
		return "***"
	}
	return s[:3] + "****" + s[len(s)-3:]
}

