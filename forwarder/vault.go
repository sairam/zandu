package forwarder

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// VaultProvider reads secrets from HashiCorp Vault (or OpenBao). References
// have the form "<api path>#<field>", for example
// "secret/data/dynadot#api_key" for a KV v2 mount. KV v1 paths work too.
//
// It authenticates with a static token, a token file kept fresh by Vault
// Agent, or AppRole credentials.
type VaultProvider struct {
	Addr      string
	Namespace string
	// Token is a static token. TokenFile is re-read whenever Vault rejects
	// the current token.
	Token     string
	TokenFile string
	// RoleID and SecretID enable AppRole login at AppRoleMount
	// (default "approle").
	RoleID       string
	SecretID     string
	AppRoleMount string
	Client       *http.Client

	mu    sync.Mutex
	token string
}

// VaultFromEnv configures a provider from the standard VAULT_ADDR,
// VAULT_TOKEN, VAULT_NAMESPACE variables plus VAULT_TOKEN_FILE,
// VAULT_ROLE_ID, VAULT_SECRET_ID and VAULT_APPROLE_MOUNT. It returns nil when
// VAULT_ADDR is not set.
func VaultFromEnv() *VaultProvider {
	addr := os.Getenv("VAULT_ADDR")
	if addr == "" {
		return nil
	}
	return &VaultProvider{
		Addr:         strings.TrimSuffix(addr, "/"),
		Namespace:    os.Getenv("VAULT_NAMESPACE"),
		Token:        os.Getenv("VAULT_TOKEN"),
		TokenFile:    os.Getenv("VAULT_TOKEN_FILE"),
		RoleID:       os.Getenv("VAULT_ROLE_ID"),
		SecretID:     os.Getenv("VAULT_SECRET_ID"),
		AppRoleMount: os.Getenv("VAULT_APPROLE_MOUNT"),
	}
}

var errVaultDenied = errors.New("permission denied")

// Resolve implements SecretProvider.
func (v *VaultProvider) Resolve(ctx context.Context, ref string) (string, error) {
	path, field, _ := strings.Cut(ref, "#")
	tok, err := v.currentToken(ctx, false)
	if err != nil {
		return "", err
	}
	data, err := v.read(ctx, path, tok)
	if errors.Is(err, errVaultDenied) {
		// The token may have expired; obtain a new one and retry once.
		if tok, err = v.currentToken(ctx, true); err != nil {
			return "", err
		}
		data, err = v.read(ctx, path, tok)
	}
	if err != nil {
		return "", err
	}
	// KV v2 nests the secret under data.data alongside data.metadata.
	if inner, ok := data["data"].(map[string]any); ok {
		if _, isV2 := data["metadata"]; isV2 {
			data = inner
		}
	}
	return lookupKey(data, field)
}

func (v *VaultProvider) currentToken(ctx context.Context, refresh bool) (string, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.token != "" && !refresh {
		return v.token, nil
	}
	switch {
	case v.RoleID != "":
		tok, err := v.appRoleLogin(ctx)
		if err != nil {
			return "", err
		}
		v.token = tok
	case v.TokenFile != "":
		b, err := os.ReadFile(v.TokenFile)
		if err != nil {
			return "", fmt.Errorf("read token file: %w", err)
		}
		v.token = strings.TrimSpace(string(b))
	case v.Token != "":
		v.token = v.Token
	default:
		return "", errors.New("no Vault credentials configured")
	}
	return v.token, nil
}

func (v *VaultProvider) appRoleLogin(ctx context.Context) (string, error) {
	mount := v.AppRoleMount
	if mount == "" {
		mount = "approle"
	}
	body, _ := json.Marshal(map[string]string{"role_id": v.RoleID, "secret_id": v.SecretID})
	var out struct {
		Auth struct {
			ClientToken string `json:"client_token"`
		} `json:"auth"`
	}
	if err := v.do(ctx, http.MethodPost, "auth/"+mount+"/login", "", bytes.NewReader(body), &out); err != nil {
		return "", fmt.Errorf("approle login: %w", err)
	}
	if out.Auth.ClientToken == "" {
		return "", errors.New("approle login: no token returned")
	}
	return out.Auth.ClientToken, nil
}

func (v *VaultProvider) read(ctx context.Context, path, token string) (map[string]any, error) {
	var out struct {
		Data map[string]any `json:"data"`
	}
	if err := v.do(ctx, http.MethodGet, path, token, nil, &out); err != nil {
		return nil, err
	}
	if out.Data == nil {
		return nil, errors.New("secret has no data")
	}
	return out.Data, nil
}

func (v *VaultProvider) do(ctx context.Context, method, path, token string, body io.Reader, out any) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, method, v.Addr+"/v1/"+strings.TrimPrefix(path, "/"), body)
	if err != nil {
		return err
	}
	if token != "" {
		req.Header.Set("X-Vault-Token", token)
	}
	if v.Namespace != "" {
		req.Header.Set("X-Vault-Namespace", v.Namespace)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	client := v.Client
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusForbidden:
		return errVaultDenied
	case resp.StatusCode == http.StatusNotFound:
		return errors.New("secret not found")
	case resp.StatusCode >= 300:
		return fmt.Errorf("vault returned %s", resp.Status)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(out)
}
