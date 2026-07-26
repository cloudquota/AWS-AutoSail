package auth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"golang.org/x/crypto/bcrypt"
)

// AWSAccount holds one set of AWS credentials.
type AWSAccount struct {
	Name           string `json:"name"`
	AK             string `json:"ak"`
	SK             string `json:"sk"`
	Proxy          string `json:"proxy,omitempty"`
	Region         string `json:"region,omitempty"`
	QuotaRegion    string `json:"quota_region,omitempty"`
	QuotaOn        string `json:"quota_on,omitempty"`
	QuotaSpot      string `json:"quota_spot,omitempty"`
	QuotaOnName    string `json:"quota_on_name,omitempty"`
	QuotaSpName    string `json:"quota_sp_name,omitempty"`
	QuotaUpdatedAt int64  `json:"quota_updated_at,omitempty"`
}

type AWSQuotaSnapshot struct {
	Region      string
	OnDemand    string
	Spot        string
	OnDemandMsg string
	SpotMsg     string
	UpdatedAt   int64
}

// AppConfig holds all persistent configuration.
type AppConfig struct {
	Username     string `json:"username"`
	PasswordHash string `json:"password_hash"`

	// Panel access control (default true)
	PanelEnabled *bool `json:"panel_enabled,omitempty"`

	// Multiple AWS accounts
	Accounts []AWSAccount `json:"accounts,omitempty"`
}

// ConfigManager manages loading/saving config from a JSON file.
type ConfigManager struct {
	mu     sync.RWMutex
	path   string
	cfg    AppConfig
	encKey []byte
}

// NewConfigManager creates a manager and loads existing config or creates defaults.
func NewConfigManager(path string) (*ConfigManager, error) {
	cm := &ConfigManager{path: path}
	if err := cm.load(); err != nil {
		if !os.IsNotExist(err) {
			return nil, err
		}
		// Create default config
		hash, _ := bcrypt.GenerateFromPassword([]byte("admin"), bcrypt.DefaultCost)
		cm.cfg = AppConfig{
			Username:     "admin",
			PasswordHash: string(hash),
		}
		if err := cm.save(); err != nil {
			return nil, err
		}
	}
	return cm, nil
}

func (cm *ConfigManager) load() error {
	data, err := os.ReadFile(cm.path)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(data, &cm.cfg); err != nil {
		return err
	}

	needsSave := false
	for i := range cm.cfg.Accounts {
		if cm.cfg.Accounts[i].AK != "" && !strings.HasPrefix(cm.cfg.Accounts[i].AK, encPrefix) {
			needsSave = true
		}
		if cm.cfg.Accounts[i].SK != "" && !strings.HasPrefix(cm.cfg.Accounts[i].SK, encPrefix) {
			needsSave = true
		}
		cm.cfg.Accounts[i].AK = cm.decryptStr(cm.cfg.Accounts[i].AK)
		cm.cfg.Accounts[i].SK = cm.decryptStr(cm.cfg.Accounts[i].SK)
	}

	// Wait, we cannot recursively call cm.save() properly if NewConfigManager hasn't finished, 
    // but cm.save() is public so it's safe to call.
	if needsSave {
		return cm.save()
	}
	return nil
}

func (cm *ConfigManager) save() error {
	cfgCopy := cm.cfg
	cfgCopy.Accounts = make([]AWSAccount, len(cm.cfg.Accounts))
	copy(cfgCopy.Accounts, cm.cfg.Accounts)

	for i := range cfgCopy.Accounts {
		cfgCopy.Accounts[i].AK = cm.encryptStr(cfgCopy.Accounts[i].AK)
		cfgCopy.Accounts[i].SK = cm.encryptStr(cfgCopy.Accounts[i].SK)
	}

	data, err := json.MarshalIndent(cfgCopy, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(cm.path, data, 0600)
}

const encPrefix = "ENC:"

func (cm *ConfigManager) getEncKey() []byte {
	if len(cm.encKey) == 32 {
		return cm.encKey
	}
	keyPath := filepath.Join(filepath.Dir(cm.path), ".aes_key")
	keyData, err := os.ReadFile(keyPath)
	if err == nil && len(keyData) == 32 {
		cm.encKey = keyData
		return cm.encKey
	}
	cm.encKey = make([]byte, 32)
	rand.Read(cm.encKey)
	os.WriteFile(keyPath, cm.encKey, 0600)
	return cm.encKey
}

func (cm *ConfigManager) encryptStr(text string) string {
	if text == "" {
		return ""
	}
	c, err := aes.NewCipher(cm.getEncKey())
	if err != nil {
		return text
	}
	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return text
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return text
	}
	sealed := gcm.Seal(nonce, nonce, []byte(text), nil)
	return encPrefix + base64.StdEncoding.EncodeToString(sealed)
}

func (cm *ConfigManager) decryptStr(cryptoText string) string {
	if !strings.HasPrefix(cryptoText, encPrefix) {
		return cryptoText
	}
	b64 := strings.TrimPrefix(cryptoText, encPrefix)
	data, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return cryptoText
	}
	c, err := aes.NewCipher(cm.getEncKey())
	if err != nil {
		return cryptoText
	}
	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return cryptoText
	}
	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return cryptoText
	}
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plain, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return cryptoText
	}
	return string(plain)
}

// Get returns a copy of the current config.
func (cm *ConfigManager) Get() AppConfig {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	return cm.cfg
}

// CheckPassword verifies a plaintext password against the stored hash.
func (cm *ConfigManager) CheckPassword(plain string) bool {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	return bcrypt.CompareHashAndPassword([]byte(cm.cfg.PasswordHash), []byte(plain)) == nil
}

// SetAccount updates username and password.
func (cm *ConfigManager) SetAccount(username, plainPassword string) error {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	if username != "" {
		cm.cfg.Username = username
	}
	if plainPassword != "" {
		hash, err := bcrypt.GenerateFromPassword([]byte(plainPassword), bcrypt.DefaultCost)
		if err != nil {
			return err
		}
		cm.cfg.PasswordHash = string(hash)
	}
	return cm.save()
}

// IsPanelEnabled returns whether the web panel is enabled (defaults to true).
func (cm *ConfigManager) IsPanelEnabled() bool {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	if cm.cfg.PanelEnabled == nil {
		return true
	}
	return *cm.cfg.PanelEnabled
}

// SetPanelEnabled toggles the web panel on or off.
func (cm *ConfigManager) SetPanelEnabled(enabled bool) error {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	cm.cfg.PanelEnabled = &enabled
	return cm.save()
}

// --- Multi-Account Management ---

// GetAccounts returns a copy of the accounts list.
func (cm *ConfigManager) GetAccounts() []AWSAccount {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	out := make([]AWSAccount, len(cm.cfg.Accounts))
	copy(out, cm.cfg.Accounts)
	return out
}

// GetAccountByName returns the account with the given name.
func (cm *ConfigManager) GetAccountByName(name string) (AWSAccount, bool) {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	for _, a := range cm.cfg.Accounts {
		if a.Name == name {
			return a, true
		}
	}
	return AWSAccount{}, false
}

func copyStoredAccountState(dst *AWSAccount, src AWSAccount) {
	if dst.SK == "" {
		dst.SK = src.SK
	}
	if dst.QuotaRegion == "" {
		dst.QuotaRegion = src.QuotaRegion
	}
	if dst.QuotaOn == "" {
		dst.QuotaOn = src.QuotaOn
	}
	if dst.QuotaSpot == "" {
		dst.QuotaSpot = src.QuotaSpot
	}
	if dst.QuotaOnName == "" {
		dst.QuotaOnName = src.QuotaOnName
	}
	if dst.QuotaSpName == "" {
		dst.QuotaSpName = src.QuotaSpName
	}
	if dst.QuotaUpdatedAt == 0 {
		dst.QuotaUpdatedAt = src.QuotaUpdatedAt
	}
}

// AddAccount adds or updates an AWS account by name.
// If an account with the same name exists, it is updated (sk="" means keep old).
func (cm *ConfigManager) AddAccount(acct AWSAccount) error {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	for i, a := range cm.cfg.Accounts {
		if a.Name == acct.Name {
			// update existing — keep old SK if new one is empty
			copyStoredAccountState(&acct, a)
			cm.cfg.Accounts[i] = acct
			return cm.save()
		}
	}
	cm.cfg.Accounts = append(cm.cfg.Accounts, acct)
	return cm.save()
}

// RemoveAccount removes an account by name.
func (cm *ConfigManager) RemoveAccount(name string) error {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	for i, a := range cm.cfg.Accounts {
		if a.Name == name {
			cm.cfg.Accounts = append(cm.cfg.Accounts[:i], cm.cfg.Accounts[i+1:]...)
			return cm.save()
		}
	}
	return fmt.Errorf("account %q not found", name)
}

// UpdateAccountKeys updates the AK and SK for the named account.
func (cm *ConfigManager) UpdateAccountKeys(name, newAK, newSK string) error {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	for i, a := range cm.cfg.Accounts {
		if a.Name == name {
			cm.cfg.Accounts[i].AK = newAK
			cm.cfg.Accounts[i].SK = newSK
			return cm.save()
		}
	}
	return fmt.Errorf("account %q not found", name)
}

// UpdateAccount updates an account identified by oldName with new data (supports renaming).
func (cm *ConfigManager) UpdateAccount(oldName string, acct AWSAccount) error {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	for i, a := range cm.cfg.Accounts {
		if a.Name == oldName {
			copyStoredAccountState(&acct, a)
			cm.cfg.Accounts[i] = acct
			return cm.save()
		}
	}
	return fmt.Errorf("account %q not found", oldName)
}

func (cm *ConfigManager) UpdateAccountQuota(name string, snap AWSQuotaSnapshot) error {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	for i, a := range cm.cfg.Accounts {
		if a.Name == name {
			a.QuotaRegion = snap.Region
			a.QuotaOn = snap.OnDemand
			a.QuotaSpot = snap.Spot
			a.QuotaOnName = snap.OnDemandMsg
			a.QuotaSpName = snap.SpotMsg
			a.QuotaUpdatedAt = snap.UpdatedAt
			cm.cfg.Accounts[i] = a
			return cm.save()
		}
	}
	return fmt.Errorf("account %q not found", name)
}
