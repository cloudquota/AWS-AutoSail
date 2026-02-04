package main

import (
	"crypto/rand"
	"encoding/hex"
	"html/template"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/patrickmn/go-cache"

	"aws-lightsail-go/internal/aws"
	"aws-lightsail-go/internal/session"
	"aws-lightsail-go/internal/store"
)

type Flash struct {
	Success string
	Error   string
	Warn    string
	Info    string
}

type PageData struct {
	Title     string
	CSRFToken string

	Username string

	HasCreds    bool
	KeyName     string
	AK          string
	Proxy       string
	Keys        []store.Key
	ActiveKeyID int64
	ActiveKey   string
	PendingKey  int64

	Region  string
	Regions []RegionOption
	AZ      string

	// Tabs: create/manage/quota
	Tab string

	Flash Flash

	// Create form
	CreateEnableFW  bool
	CreateIPType    string
	CreateBlueprint string
	CreateBundle    string
	CreateRootPwd   string

	Blueprints []Option
	Bundles    []Option
	IPTypes    []Option

	// Proxy check
	ProxyExitIP  string
	ProxyExitASN string

	// Manage
	Instances []aws.InstanceView

	// Quota
	QuotaRegion string
	QuotaOn     string
	QuotaSpot   string
	QuotaOnName string
	QuotaSpName string
}

var (
	// cache instances list for 10s
	instCache = cache.New(10*time.Second, 30*time.Second)
	appStore  *store.Store
	loginHint string
)

type RegionOption struct {
	ID   string
	Name string
}

type Option struct {
	ID   string
	Name string
}

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

var regionOptions = []RegionOption{
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

var blueprintOptions = []Option{
	{ID: "ubuntu_24_04", Name: "Ubuntu 24.04 LTS"},
	{ID: "ubuntu_22_04", Name: "Ubuntu 22.04 LTS"},
	{ID: "debian_12", Name: "Debian 12"},
	{ID: "debian_11", Name: "Debian 11"},
	{ID: "centos_7", Name: "CentOS 7"},
}

var bundleOptions = []Option{
	{ID: "nano_3_0", Name: "nano (2 vCPUs, 内存 0.5 GB, 硬盘 20 GB, 流量 1024 GB / 月)"},
	{ID: "micro_3_0", Name: "micro (2 vCPUs, 内存 1 GB, 硬盘 40 GB, 流量 2048 GB / 月)"},
	{ID: "small_3_0", Name: "small (2 vCPUs, 内存 2 GB, 硬盘 60 GB, 流量 3072 GB / 月)"},
	{ID: "medium_3_0", Name: "medium (2 vCPUs, 内存 4 GB, 硬盘 80 GB, 流量 4096 GB / 月)"},
	{ID: "large_3_0", Name: "large (2 vCPUs, 内存 8 GB, 硬盘 160 GB, 流量 5120 GB / 月)"},
}

var ipTypeOptions = []Option{
	{ID: "dualstack", Name: "双栈（IPv4+IPv6）"},
	{ID: "ipv6", Name: "仅 IPv6（IPv6-only）"},
	{ID: "ipv4", Name: "仅 IPv4"},
}

var ipv6BundleMap = map[string]string{
	"nano_3_0":   "nano_ipv6_3_0",
	"micro_3_0":  "micro_ipv6_3_0",
	"small_3_0":  "small_ipv6_3_0",
	"medium_3_0": "medium_ipv6_3_0",
	"large_3_0":  "large_ipv6_3_0",
}

func regionLabel(id string) string {
	for _, r := range regionOptions {
		if r.ID == id {
			return r.Name
		}
	}
	return id
}

// 防止 region 被存坏（a/b/c 或 us-east-1a）导致 ResolveEndpointV2 not found
func normalizeRegion(r string) string {
	r = strings.TrimSpace(r)
	if r == "a" || r == "b" || r == "c" {
		return "us-east-1"
	}
	if len(r) >= 2 {
		last := r[len(r)-1]
		if (last == 'a' || last == 'b' || last == 'c') && strings.Contains(r, "-") {
			p := r[len(r)-2]
			if p >= '0' && p <= '9' { // us-east-1a
				return r[:len(r)-1]
			}
		}
	}
	return r
}

func genSessionID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func genCSRFToken() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func main() {
	var err error
	port := mustEnvInt("PORT", 9000)
	dbPath := strings.TrimSpace(os.Getenv("DB_PATH"))
	if dbPath == "" {
		dbPath = filepath.Join("data", "app.db")
	}
	if err := os.MkdirAll(filepath.Dir(dbPath), 0o755); err != nil {
		panic(err)
	}

	appStore, err = store.NewSQLiteStore(dbPath)
	if err != nil {
		panic(err)
	}

	defaultUsername := strings.TrimSpace(os.Getenv("APP_USERNAME"))
	if defaultUsername == "" {
		defaultUsername = "admin"
		loginHint = "未设置 APP_USERNAME/APP_PASSWORD，已启用默认账号 admin / admin123，请尽快修改。"
	}
	defaultPassword := strings.TrimSpace(os.Getenv("APP_PASSWORD"))
	if defaultPassword == "" {
		defaultPassword = "admin123"
		if loginHint == "" {
			loginHint = "未设置 APP_USERNAME/APP_PASSWORD，已启用默认账号 admin / admin123，请尽快修改。"
		}
	}
	if _, err := appStore.EnsureUser(defaultUsername, defaultPassword); err != nil {
		panic(err)
	}

	r := gin.New()
	r.Use(gin.Logger(), gin.Recovery())

	// templates
	r.SetFuncMap(template.FuncMap{
		"regionLabel": regionLabel,
	})
	r.LoadHTMLGlob("templates/*.html")

	// session store
	store := session.NewStore()

	// Middleware: get/create session
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

	r.Use(func(c *gin.Context) {
		s := session.Must(c)
		token := strings.TrimSpace(s.GetString("csrf_token", ""))
		if token == "" {
			token = genCSRFToken()
			s.SetString("csrf_token", token)
		}
		c.Set("csrf_token", token)
		if c.Request.Method == http.MethodPost {
			formToken := strings.TrimSpace(c.PostForm("csrf_token"))
			if formToken == "" || formToken != token {
				if c.Request.URL.Path == "/login" {
					c.Redirect(http.StatusFound, "/login?msg=csrf")
				} else {
					c.Redirect(http.StatusFound, "/?msg=csrf")
				}
				c.Abort()
				return
			}
		}
		c.Next()
	})

	r.GET("/login", func(c *gin.Context) {
		if isLoggedIn(session.Must(c)) {
			c.Redirect(http.StatusFound, "/")
			return
		}
		s := session.Must(c)
		data := PageData{
			Title:     "AutoSail 登录",
			CSRFToken: s.GetString("csrf_token", ""),
		}
		switch c.Query("msg") {
		case "bad":
			data.Flash.Error = "用户名或密码错误"
		case "csrf":
			data.Flash.Error = "请求已失效，请重试"
		case "logout":
			data.Flash.Info = "已退出登录"
		}
		if loginHint != "" && data.Flash.Error == "" {
			data.Flash.Info = loginHint
		}
		c.HTML(http.StatusOK, "login", data)
	})

	r.POST("/login", func(c *gin.Context) {
		username := strings.TrimSpace(c.PostForm("username"))
		password := strings.TrimSpace(c.PostForm("password"))
		user, err := appStore.AuthenticateUser(c.Request.Context(), username, password)
		if err != nil {
			c.Redirect(http.StatusFound, "/login?msg=bad")
			return
		}
		s := session.Must(c)
		s.SetString("user_id", strconv.FormatInt(user.ID, 10))
		s.SetString("username", user.Username)
		c.Redirect(http.StatusFound, "/")
	})

	r.POST("/logout", func(c *gin.Context) {
		s := session.Must(c)
		s.SetString("user_id", "")
		s.SetString("username", "")
		s.SetString("key_id", "")
		s.SetString("pending_key_id", "")
		c.Redirect(http.StatusFound, "/login?msg=logout")
	})

	r.Use(func(c *gin.Context) {
		if c.Request.Method == http.MethodPost && c.Request.URL.Path == "/login" {
			c.Next()
			return
		}
		if c.Request.URL.Path == "/login" {
			c.Next()
			return
		}
		if !isLoggedIn(session.Must(c)) {
			c.Redirect(http.StatusFound, "/login")
			c.Abort()
			return
		}
		c.Next()
	})

	r.GET("/", func(c *gin.Context) {
		s := session.Must(c)
		userID, _ := userIDFromSession(s)

		tab := c.Query("tab")
		if tab == "" {
			tab = s.GetString("tab", "create")
		} else {
			s.SetString("tab", tab)
		}

		region := normalizeRegion(c.Query("region"))
		if region == "" {
			region = normalizeRegion(s.GetString("region", "us-east-1"))
		}
		// 确保 session 一直是规范 region
		s.SetString("region", region)

		az := c.Query("az")
		if az == "" {
			az = s.GetString("az", "a")
		} else {
			s.SetString("az", az)
		}

		username := s.GetString("username", "")
		keys, _ := appStore.ListKeys(c.Request.Context(), userID)
		activeKey, _ := resolveActiveKey(s, keys)
		pendingKeyID := resolvePendingKeyID(s, keys, activeKey)
		pendingKey := findKeyByID(keys, pendingKeyID)
		formKey := pendingKey
		if formKey == nil {
			formKey = activeKey
		}

		// Create UI defaults (persist in session)
		createIPType := s.GetString("create_ip_type", "dualstack")
		createBlueprint := s.GetString("create_blueprint", "ubuntu_24_04")
		createBundle := s.GetString("create_bundle", "nano_3_0")
		createFW := s.GetString("create_fw_all", "1") == "1"

		activeAK := strings.TrimSpace(keyAccessKey(activeKey))
		activeProxy := strings.TrimSpace(keyProxy(activeKey))
		activeHasCreds := activeKey != nil && activeAK != "" && strings.TrimSpace(activeKey.SecretKey) != ""

		data := PageData{
			Title:           "AutoSail",
			CSRFToken:       s.GetString("csrf_token", ""),
			Username:        username,
			HasCreds:        activeHasCreds,
			KeyName:         keyName(formKey),
			AK:              keyAccessKey(formKey),
			Proxy:           keyProxy(formKey),
			Keys:            keys,
			ActiveKeyID:     keyID(activeKey),
			ActiveKey:       keyName(activeKey),
			PendingKey:      pendingKeyID,
			Region:          region,
			Regions:         regionOptions,
			AZ:              az,
			Tab:             tab,
			CreateIPType:    createIPType,
			CreateBlueprint: createBlueprint,
			CreateBundle:    createBundle,
			CreateEnableFW:  createFW,
			Blueprints:      blueprintOptions,
			Bundles:         bundleOptions,
			IPTypes:         ipTypeOptions,
		}

		switch c.Query("msg") {
		case "cleared":
			data.Flash.Success = "已删除当前密钥"
		case "saved":
			data.Flash.Success = "已保存（已新增密钥）"
		case "activated":
			data.Flash.Success = "已启用选中的密钥"
		case "updated":
			data.Flash.Success = "已更新选中的密钥"
		case "csrf":
			data.Flash.Error = "请求已失效，请刷新页面后重试"
		case "needuse":
			data.Flash.Warn = "请先选择密钥并点击“使用此密钥”"
		case "needkey":
			data.Flash.Warn = "Access Key / Secret Key 不能为空"
		case "needids":
			data.Flash.Warn = "Blueprint / Bundle 不能为空"
		case "err_client":
			data.Flash.Error = "AWS 客户端初始化失败"
		case "created":
			data.Flash.Success = "✅ 创建请求已提交（稍等 1-2 分钟后去『管理』查看）"
		case "create_failed":
			data.Flash.Error = "创建失败：请查看服务器日志/检查权限/区域是否可用"
		case "quota_ok":
			data.Flash.Success = "✅ 配额测试完成"
		case "quota_err":
			data.Flash.Error = "配额测试失败：未找到配额项或没有 Service Quotas 权限"
		case "reboot_ok":
			data.Flash.Success = "已提交重启"
		case "reboot_failed":
			data.Flash.Error = "重启失败（详情看日志）"
		case "openall_ok":
			data.Flash.Success = "已提交全端口开放"
		case "openall_failed":
			data.Flash.Error = "全端口开放失败（详情看日志）"
		case "swapip_ok":
			data.Flash.Success = "✅ 换静态 IP 已提交/完成（如刚申请需稍等同步）"
		case "swapip_failed":
			data.Flash.Error = "换静态 IP 失败（可能是 IPv6-only 或额度/权限问题）"
		case "delete_ok":
			data.Flash.Success = "已提交删除（如有静态 IP 已尝试释放）"
		case "delete_failed":
			data.Flash.Error = "删除失败（详情看日志）"
		}

		// manage list
		if tab == "manage" && activeHasCreds {
			key := strings.Join([]string{"inst", region, activeAK, activeProxy}, "|")
			if v, ok := instCache.Get(key); ok {
				data.Instances = v.([]aws.InstanceView)
			} else {
				cli, err := aws.NewLightsailClient(c.Request.Context(), region, activeAK, activeKey.SecretKey, activeProxy)
				if err != nil {
					data.Flash.Error = "创建 Lightsail client 失败：" + err.Error()
				} else {
					list, err := aws.ListInstances(c.Request.Context(), cli)
					if err != nil {
						data.Flash.Error = "拉取实例失败：" + err.Error()
					} else {
						data.Instances = list
						instCache.Set(key, list, cache.DefaultExpiration)
					}
				}
			}
		} else if tab == "manage" && !activeHasCreds {
			data.Flash.Warn = "请先启用一个有效密钥再查看实例列表"
		}

		// quota result from session
		if tab == "quota" {
			data.QuotaRegion = s.GetString("quota_region", region)
			data.QuotaOn = s.GetString("quota_on", "")
			data.QuotaSpot = s.GetString("quota_spot", "")
			data.QuotaOnName = s.GetString("quota_on_name", "")
			data.QuotaSpName = s.GetString("quota_sp_name", "")
		}

		c.HTML(http.StatusOK, "layout", data)
	})

	// Save creds (留空不覆盖)
	r.POST("/auth/save", func(c *gin.Context) {
		s := session.Must(c)
		userID, _ := userIDFromSession(s)

		mode := strings.TrimSpace(c.PostForm("mode"))
		keyIDStr := strings.TrimSpace(c.PostForm("key_id"))
		ak := strings.TrimSpace(c.PostForm("ak"))
		sk := strings.TrimSpace(c.PostForm("sk"))
		proxy := strings.TrimSpace(c.PostForm("proxy"))

		if mode == "update" && keyIDStr != "" {
			if keyID, err := strconv.ParseInt(keyIDStr, 10, 64); err == nil && keyID > 0 {
				keys, _ := appStore.ListKeys(c.Request.Context(), userID)
				if existing := findKeyByID(keys, keyID); existing != nil {
					keyName := strings.TrimSpace(c.PostForm("key_name"))
					if keyName == "" {
						keyName = existing.Name
					}
					if ak == "" {
						ak = existing.AccessKey
					}
					if sk == "" {
						sk = existing.SecretKey
					}
					if ak == "" || sk == "" {
						c.Redirect(http.StatusFound, "/?msg=needkey")
						return
					}
					if err := appStore.UpdateKey(c.Request.Context(), userID, keyID, keyName, ak, sk, proxy); err == nil {
						s.SetString("pending_key_id", strconv.FormatInt(keyID, 10))
						c.Redirect(http.StatusFound, "/?msg=updated")
						return
					}
				}
			}
		}

		keyName := strings.TrimSpace(c.PostForm("key_name"))
		if keyName == "" {
			keyName = time.Now().Format("2006-01-02 15:04")
		}
		if ak == "" || sk == "" {
			c.Redirect(http.StatusFound, "/?msg=needkey")
			return
		}
		keyID, err := appStore.CreateKey(c.Request.Context(), userID, keyName, ak, sk, proxy)
		if err == nil {
			s.SetString("pending_key_id", strconv.FormatInt(keyID, 10))
		}
		c.Redirect(http.StatusFound, "/?msg=saved")
	})

	// Select key
	r.POST("/auth/select", func(c *gin.Context) {
		s := session.Must(c)
		userID, _ := userIDFromSession(s)
		keyID := strings.TrimSpace(c.PostForm("key_id"))
		if keyID != "" {
			keys, _ := appStore.ListKeys(c.Request.Context(), userID)
			if parsedID, err := strconv.ParseInt(keyID, 10, 64); err == nil {
				if keyExists(keys, parsedID) {
					s.SetString("pending_key_id", keyID)
					s.SetString("key_id", keyID)
					c.Redirect(http.StatusFound, "/?msg=activated")
					return
				}
			}
		}
		c.Redirect(http.StatusFound, "/")
	})

	// Activate selected key
	r.POST("/auth/activate", func(c *gin.Context) {
		s := session.Must(c)
		userID, _ := userIDFromSession(s)
		keys, _ := appStore.ListKeys(c.Request.Context(), userID)
		keyID := strings.TrimSpace(c.PostForm("key_id"))
		if keyID == "" {
			keyID = strings.TrimSpace(s.GetString("pending_key_id", ""))
		}
		if keyID != "" {
			if parsedID, err := strconv.ParseInt(keyID, 10, 64); err == nil {
				if keyExists(keys, parsedID) {
					s.SetString("key_id", keyID)
					s.SetString("pending_key_id", keyID)
				}
			}
		}
		c.Redirect(http.StatusFound, "/?msg=activated")
	})

	// Delete current key
	r.POST("/auth/delete", func(c *gin.Context) {
		s := session.Must(c)
		userID, _ := userIDFromSession(s)
		keyIDStr := strings.TrimSpace(c.PostForm("key_id"))
		if keyIDStr == "" {
			keyIDStr = strings.TrimSpace(s.GetString("key_id", ""))
		}
		var deletedKeyID int64
		if keyIDStr != "" {
			if keyID, err := strconv.ParseInt(keyIDStr, 10, 64); err == nil && keyID > 0 {
				_ = appStore.DeleteKey(c.Request.Context(), userID, keyID)
				deletedKeyID = keyID
			}
		}
		keys, _ := appStore.ListKeys(c.Request.Context(), userID)
		activeKeyID, _ := strconv.ParseInt(strings.TrimSpace(s.GetString("key_id", "")), 10, 64)
		if activeKeyID == deletedKeyID || !keyExists(keys, activeKeyID) {
			activeKeyID = 0
		}
		if activeKeyID == 0 && len(keys) > 0 {
			activeKeyID = keys[0].ID
		}
		if activeKeyID > 0 {
			activeKeyIDStr := strconv.FormatInt(activeKeyID, 10)
			s.SetString("key_id", activeKeyIDStr)
			s.SetString("pending_key_id", activeKeyIDStr)
		} else {
			s.SetString("key_id", "")
			s.SetString("pending_key_id", "")
		}
		c.Redirect(http.StatusFound, "/?msg=cleared")
	})

	// Proxy exit IP check (uses current session proxy)
	r.GET("/proxy/check", func(c *gin.Context) {
		s := session.Must(c)
		proxy := strings.TrimSpace(c.Query("proxy"))
		if proxy == "" {
			userID, _ := userIDFromSession(s)
			keys, _ := appStore.ListKeys(c.Request.Context(), userID)
			activeKey, _ := resolveActiveKey(s, keys)
			proxy = keyProxy(activeKey)
		}
		ip, asn, err := aws.CheckProxyExitIP(c.Request.Context(), proxy)
		if err != nil {
			c.JSON(http.StatusOK, gin.H{"ok": false, "error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{"ok": true, "ip": ip, "as": asn})
	})

	// Create instance
	r.POST("/aws/create", func(c *gin.Context) {
		s := session.Must(c)
		userID, _ := userIDFromSession(s)
		keys, _ := appStore.ListKeys(c.Request.Context(), userID)
		activeKey, _ := resolveActiveKey(s, keys)
		if activeKey == nil || strings.TrimSpace(activeKey.AccessKey) == "" || strings.TrimSpace(activeKey.SecretKey) == "" {
			c.Redirect(http.StatusFound, "/?tab=create&msg=needuse")
			return
		}
		ak := strings.TrimSpace(activeKey.AccessKey)
		sk := strings.TrimSpace(activeKey.SecretKey)
		proxy := strings.TrimSpace(activeKey.Proxy)

		region := normalizeRegion(strings.TrimSpace(c.PostForm("region")))
		az := strings.TrimSpace(c.PostForm("az"))
		if region == "" {
			region = "us-east-1"
		}
		if az == "" {
			az = "a"
		}
		s.SetString("region", region)
		s.SetString("az", az)

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
		bundle := strings.TrimSpace(c.PostForm("bundle_id"))
		if blueprint != "" {
			s.SetString("create_blueprint", blueprint)
		}
		if bundle != "" {
			s.SetString("create_bundle", bundle)
		}
		rootPwd := strings.TrimSpace(c.PostForm("root_pwd"))

		if rootPwd == "" {
			c.Redirect(http.StatusFound, "/?tab=create&region="+region)
			return
		}
		if blueprint == "" || bundle == "" {
			c.Redirect(http.StatusFound, "/?tab=create&region="+region+"&msg=needids")
			return
		}

		// instanceName: keep it unique like python version
		instanceName := "vps-" + strconv.FormatInt(time.Now().Unix(), 10)
		userData := aws.BuildRootPasswordUserData(rootPwd)

		// If ipv6-only, use ipv6 bundle encoding (Lightsail real bundle id)
		bundleToUse := bundle
		if ipType == "ipv6" {
			if v, ok := ipv6BundleMap[bundle]; ok {
				bundleToUse = v
			}
		}

		cli, err := aws.NewLightsailClient(c.Request.Context(), region, ak, sk, proxy)
		if err != nil {
			c.Redirect(http.StatusFound, "/?tab=create&region="+region+"&msg=err_client")
			return
		}

		availabilityZone := region + az

		err = aws.CreateInstance(c.Request.Context(), cli, aws.CreateInstanceInput{
			InstanceName:     instanceName,
			AvailabilityZone: availabilityZone,
			BlueprintID:      blueprint,
			BundleID:         bundleToUse,
			UserData:         userData,
			IPAddressType:    ipType,
			EnableFWAll:      enableFW,
		})
		if err != nil {
			c.Redirect(http.StatusFound, "/?tab=create&region="+region+"&msg=create_failed")
			return
		}

		// invalidate list cache
		key := strings.Join([]string{"inst", region, ak, proxy}, "|")
		instCache.Delete(key)

		c.Redirect(http.StatusFound, "/?tab=manage&region="+region+"&msg=created")
	})

	// Manage actions
	r.POST("/aws/reboot", func(c *gin.Context) {
		doManageAction(c, "reboot", func(ctx *gin.Context, cli aws.LightsailAPI, name string) error {
			return aws.RebootInstance(ctx.Request.Context(), cli, name)
		})
	})

	r.POST("/aws/openall", func(c *gin.Context) {
		doManageAction(c, "openall", func(ctx *gin.Context, cli aws.LightsailAPI, name string) error {
			return aws.OpenAllPorts(ctx.Request.Context(), cli, name)
		})
	})

	// Clear manage list cache (per region+ak+proxy)
	r.POST("/aws/refresh", func(c *gin.Context) {
		s := session.Must(c)
		userID, _ := userIDFromSession(s)
		keys, _ := appStore.ListKeys(c.Request.Context(), userID)
		activeKey, _ := resolveActiveKey(s, keys)
		if activeKey == nil {
			c.Redirect(http.StatusFound, "/?tab=manage&msg=needuse")
			return
		}
		ak := strings.TrimSpace(activeKey.AccessKey)
		proxy := strings.TrimSpace(activeKey.Proxy)
		region := normalizeRegion(strings.TrimSpace(c.PostForm("region")))
		if region == "" {
			region = normalizeRegion(s.GetString("region", "us-east-1"))
		}
		key := strings.Join([]string{"inst", region, ak, proxy}, "|")
		instCache.Delete(key)
		c.Redirect(http.StatusFound, "/?tab=manage&region="+region)
	})

	r.POST("/aws/delete", func(c *gin.Context) {
		doManageAction(c, "delete", func(ctx *gin.Context, cli aws.LightsailAPI, name string) error {
			return aws.DeleteInstanceWithStaticIPCleanup(ctx.Request.Context(), cli, name)
		})
	})

	r.POST("/aws/swapip", func(c *gin.Context) {
		doManageAction(c, "swapip", func(ctx *gin.Context, cli aws.LightsailAPI, name string) error {
			return aws.SwapStaticIPForInstance(ctx.Request.Context(), cli, name)
		})
	})

	// Quota test
	r.POST("/aws/quota", func(c *gin.Context) {
		s := session.Must(c)
		userID, _ := userIDFromSession(s)
		keys, _ := appStore.ListKeys(c.Request.Context(), userID)
		activeKey, _ := resolveActiveKey(s, keys)
		if activeKey == nil || strings.TrimSpace(activeKey.AccessKey) == "" || strings.TrimSpace(activeKey.SecretKey) == "" {
			c.Redirect(http.StatusFound, "/?tab=quota&msg=needuse")
			return
		}
		ak := strings.TrimSpace(activeKey.AccessKey)
		sk := strings.TrimSpace(activeKey.SecretKey)
		proxy := strings.TrimSpace(activeKey.Proxy)

		region := normalizeRegion(strings.TrimSpace(c.PostForm("quota_region")))
		if region == "" {
			region = normalizeRegion(s.GetString("region", "us-east-1"))
		}
		s.SetString("quota_region", region)

		sq, err := aws.NewServiceQuotasClient(c.Request.Context(), region, ak, sk, proxy)
		if err != nil {
			s.SetString("quota_on", "")
			s.SetString("quota_spot", "")
			c.Redirect(http.StatusFound, "/?tab=quota&msg=quota_err")
			return
		}

		onVal, spotVal, onName, spotName, err := aws.TestVCPUQuotas(c.Request.Context(), sq)
		if err != nil || (strings.TrimSpace(onVal) == "" && strings.TrimSpace(spotVal) == "") {
			s.SetString("quota_on", "")
			s.SetString("quota_spot", "")
			s.SetString("quota_on_name", "")
			s.SetString("quota_sp_name", "")
			c.Redirect(http.StatusFound, "/?tab=quota&msg=quota_err")
			return
		}

		s.SetString("quota_on", onVal)
		s.SetString("quota_spot", spotVal)
		s.SetString("quota_on_name", onName)
		s.SetString("quota_sp_name", spotName)

		c.Redirect(http.StatusFound, "/?tab=quota&msg=quota_ok")
	})

	_ = r.Run(":" + strconv.Itoa(port))
}

func doManageAction(c *gin.Context, action string, fn func(ctx *gin.Context, cli aws.LightsailAPI, name string) error) {
	s := session.Must(c)
	userID, _ := userIDFromSession(s)
	keys, _ := appStore.ListKeys(c.Request.Context(), userID)
	activeKey, _ := resolveActiveKey(s, keys)
	if activeKey == nil {
		c.Redirect(http.StatusFound, "/?tab=manage&msg=needuse")
		return
	}
	ak := strings.TrimSpace(activeKey.AccessKey)
	sk := strings.TrimSpace(activeKey.SecretKey)
	proxy := strings.TrimSpace(activeKey.Proxy)

	region := normalizeRegion(strings.TrimSpace(c.PostForm("region")))
	if region == "" {
		region = normalizeRegion(s.GetString("region", "us-east-1"))
	}
	name := strings.TrimSpace(c.PostForm("instance"))
	if name == "" {
		c.Redirect(http.StatusFound, "/?tab=manage&region="+region)
		return
	}
	if ak == "" || sk == "" {
		c.Redirect(http.StatusFound, "/?tab=manage&region="+region)
		return
	}

	cli, err := aws.NewLightsailClient(c.Request.Context(), region, ak, sk, proxy)
	if err != nil {
		c.Redirect(http.StatusFound, "/?tab=manage&region="+region+"&msg=err_client")
		return
	}

	if err := fn(c, cli, name); err != nil {
		c.Redirect(http.StatusFound, "/?tab=manage&region="+region+"&msg="+action+"_failed")
		return
	}

	// invalidate cache
	key := strings.Join([]string{"inst", region, ak, proxy}, "|")
	instCache.Delete(key)

	c.Redirect(http.StatusFound, "/?tab=manage&region="+region+"&msg="+action+"_ok")
}

func isLoggedIn(s *session.Session) bool {
	return strings.TrimSpace(s.GetString("user_id", "")) != ""
}

func userIDFromSession(s *session.Session) (int64, bool) {
	idStr := strings.TrimSpace(s.GetString("user_id", ""))
	if idStr == "" {
		return 0, false
	}
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		return 0, false
	}
	return id, true
}

func resolveActiveKey(s *session.Session, keys []store.Key) (*store.Key, bool) {
	if len(keys) == 0 {
		return nil, false
	}
	keyIDStr := strings.TrimSpace(s.GetString("key_id", ""))
	if keyIDStr != "" {
		if keyID, err := strconv.ParseInt(keyIDStr, 10, 64); err == nil {
			for i := range keys {
				if keys[i].ID == keyID {
					return &keys[i], true
				}
			}
		}
	}
	return nil, false
}

func resolvePendingKeyID(s *session.Session, keys []store.Key, activeKey *store.Key) int64 {
	keyIDStr := strings.TrimSpace(s.GetString("pending_key_id", ""))
	if keyIDStr != "" {
		if keyID, err := strconv.ParseInt(keyIDStr, 10, 64); err == nil {
			if keyExists(keys, keyID) {
				return keyID
			}
		}
	}
	if activeKey != nil {
		return activeKey.ID
	}
	return 0
}

func keyExists(keys []store.Key, keyID int64) bool {
	for _, key := range keys {
		if key.ID == keyID {
			return true
		}
	}
	return false
}

func findKeyByID(keys []store.Key, keyID int64) *store.Key {
	if keyID == 0 {
		return nil
	}
	for i := range keys {
		if keys[i].ID == keyID {
			return &keys[i]
		}
	}
	return nil
}

func keyName(k *store.Key) string {
	if k == nil {
		return ""
	}
	return k.Name
}

func keyAccessKey(k *store.Key) string {
	if k == nil {
		return ""
	}
	return k.AccessKey
}

func keyProxy(k *store.Key) string {
	if k == nil {
		return ""
	}
	return k.Proxy
}

func keyID(k *store.Key) int64 {
	if k == nil {
		return 0
	}
	return k.ID
}
