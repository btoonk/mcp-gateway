package main

import (
    "context"
    "bytes"
    "io"
    "encoding/json"
    "errors"
    "flag"
    "fmt"
    "log"
    "net/http"
    "os"
    "os/exec"
    "crypto/rsa"
    "encoding/base64"
    "math/big"
    "strings"
    "sync"
    "time"

    "github.com/modelcontextprotocol/go-sdk/mcp"
    jwt "github.com/golang-jwt/jwt/v5"
)

// simple types for the demo tools
type emptyArgs struct{}

// infoHandler returns basic gateway info.
func infoHandler(_ context.Context, _ *mcp.CallToolRequest, _ emptyArgs) (*mcp.CallToolResult, any, error) {
	msg := "mcp-gateway: static tool list; proxy not yet implemented"
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: msg}}}, nil, nil
}

// proxyHandler is a placeholder that makes it clear calling is not implemented yet.
type proxyArgs struct {
	Target string `json:"target" jsonschema:"A description or URL for the upstream target"`
}

func proxyHandler(_ context.Context, _ *mcp.CallToolRequest, _ proxyArgs) (*mcp.CallToolResult, any, error) {
	// Returning a regular error here is wrapped by the SDK into a tool error
	// (result.IsError=true with appropriate content), per ToolHandlerFor behavior.
	return nil, nil, fmt.Errorf("proxy not implemented yet")
}

// UpstreamConfig declares an upstream MCP server.
type UpstreamConfig struct {
    Name        string `json:"name"`
    Type        string `json:"type"` // e.g. "http"
    URL         string `json:"url"`
    BearerToken string `json:"bearerToken,omitempty"`
    // Tools: optional allowlist of tool names exposed from this upstream.
    // Omit or ["*"] to allow all tools.
    Tools       []string `json:"tools,omitempty"`
    // For type=="stdio": local process execution settings
    Command     string            `json:"command,omitempty"`
    Args        []string          `json:"args,omitempty"`
    Env         map[string]string `json:"env,omitempty"`
}

// Config is the gateway configuration.
type Config struct {
    Upstreams []UpstreamConfig `json:"upstreams"`
    Identities []IdentityConfig `json:"identities"`
    Policies  []PolicyConfig   `json:"policies"`
    Providers []OAuthProviderConfig `json:"providers"`
}

// upstream represents a live connection to a single upstream MCP server.
type upstream struct {
    cfg    UpstreamConfig
    client *mcp.Client
    sess   *mcp.ClientSession
    cancel context.CancelFunc
    // entries discovered from upstream keyed by original tool name.
    entries map[string]*toolEntry
    // allowedTools: nil => all tools allowed; otherwise allowlist
    allowedTools map[string]struct{}
}

type toolEntry struct {
    upstreamName string
    upstreamTool *mcp.Tool // Name is the original upstream name
    handler      mcp.ToolHandler
}

// manager holds upstreams and updates the catalog of tools.
type manager struct {
    mu        sync.Mutex
    upstreams map[string]*upstream
}

func newManager() *manager {
    return &manager{upstreams: make(map[string]*upstream)}
}

func (m *manager) addUpstream(ctx context.Context, cfg UpstreamConfig) error {
	m.mu.Lock()
	if _, exists := m.upstreams[cfg.Name]; exists {
		m.mu.Unlock()
		return fmt.Errorf("duplicate upstream name: %s", cfg.Name)
	}
	m.mu.Unlock()

	// Build transport for the upstream type (support http for now).
	var transport mcp.Transport
    switch cfg.Type {
    case "http", "streamable", "http-streamable":
        httpClient := &http.Client{Timeout: 60 * time.Second}
        if cfg.BearerToken != "" {
            httpClient.Transport = roundTripperWithAuth(http.DefaultTransport, cfg.BearerToken)
        }
        transport = &mcp.StreamableClientTransport{Endpoint: cfg.URL, HTTPClient: httpClient}
    case "stdio":
        if cfg.Command == "" {
            return fmt.Errorf("stdio upstream %q requires 'command'", cfg.Name)
        }
        cmd := exec.CommandContext(ctx, cfg.Command, cfg.Args...)
        if len(cfg.Env) > 0 {
            env := os.Environ()
            for k, v := range cfg.Env {
                env = append(env, fmt.Sprintf("%s=%s", k, v))
            }
            cmd.Env = env
        }
        transport = &mcp.CommandTransport{Command: cmd}
    default:
        return fmt.Errorf("unsupported upstream type %q", cfg.Type)
    }

	// Create client with a tool-list change handler to refresh registrations.
	client := mcp.NewClient(&mcp.Implementation{
		Name:    "mcp-gateway-upstream-client",
		Version: "0.1.0",
	}, &mcp.ClientOptions{
		ToolListChangedHandler: func(ctx context.Context, _ *mcp.ToolListChangedRequest) {
			if err := m.refreshUpstream(ctx, cfg.Name); err != nil {
				log.Printf("upstream %s tool refresh failed: %v", cfg.Name, err)
			}
		},
	})

	// Connect
	sess, err := client.Connect(ctx, transport, nil)
	if err != nil {
		return fmt.Errorf("connect upstream %s: %w", cfg.Name, err)
	}

    cctx, cancel := context.WithCancel(ctx)
    up := &upstream{cfg: cfg, client: client, sess: sess, cancel: cancel, entries: make(map[string]*toolEntry)}
    // compute allowed tools from cfg.Tools (nil => all; "*" => all)
    if len(cfg.Tools) == 0 || (len(cfg.Tools) == 1 && cfg.Tools[0] == "*") {
        up.allowedTools = nil
    } else {
        up.allowedTools = make(map[string]struct{}, len(cfg.Tools))
        for _, t := range cfg.Tools {
            up.allowedTools[t] = struct{}{}
        }
    }

	m.mu.Lock()
	m.upstreams[cfg.Name] = up
	m.mu.Unlock()

	// Initial tool sync
	if err := m.refreshUpstream(cctx, cfg.Name); err != nil {
		return fmt.Errorf("initial tool sync for %s: %w", cfg.Name, err)
	}

	return nil
}

func (m *manager) refreshUpstream(ctx context.Context, name string) error {
	m.mu.Lock()
	up, ok := m.upstreams[name]
	m.mu.Unlock()
	if !ok {
		return fmt.Errorf("unknown upstream %q", name)
	}

	// List tools from upstream
	res, err := up.sess.ListTools(ctx, nil)
	if err != nil {
		return fmt.Errorf("list tools: %w", err)
	}

    // Rebuild catalog entries for this upstream
    m.mu.Lock()
    up.entries = make(map[string]*toolEntry)
    m.mu.Unlock()

    // Create entry per upstream tool with forwarder handler
    for _, t := range res.Tools {
        // Build a forwarder handler capturing original name.
        origName := t.Name
        forward := func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
            // Forward arguments verbatim.
            arguments := any(nil)
            if req != nil && req.Params != nil && len(req.Params.Arguments) > 0 {
                // Preserve raw JSON by using json.RawMessage so we don't re-marshal.
                arguments = json.RawMessage(req.Params.Arguments)
            }
            out, err := up.sess.CallTool(ctx, &mcp.CallToolParams{Name: origName, Arguments: arguments})
            if err != nil {
                return nil, err
            }
            // Ensure Content is not nil to avoid null in JSON.
            if out != nil && out.Content == nil {
                out2 := *out
                out2.Content = []mcp.Content{}
                return &out2, nil
            }
            return out, nil
        }
        // Store entry in catalog with original upstream tool name.
        toolCopy := *t
        toolCopy.Name = origName // ensure original name
        m.mu.Lock()
        up.entries[origName] = &toolEntry{upstreamName: name, upstreamTool: &toolCopy, handler: forward}
        m.mu.Unlock()
    }

    return nil
}

// roundTripperWithAuth injects Authorization header.
func roundTripperWithAuth(base http.RoundTripper, token string) http.RoundTripper {
	if base == nil {
		base = http.DefaultTransport
	}
	return roundTripperFunc(func(r *http.Request) (*http.Response, error) {
		clone := r.Clone(r.Context())
		if token != "" {
			clone.Header.Set("Authorization", "Bearer "+token)
		}
		return base.RoundTrip(clone)
	})
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func loadConfig(path string) (Config, error) {
	if path == "" {
		return Config{}, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return Config{}, err
	}
	defer f.Close()
	var cfg Config
	dec := json.NewDecoder(f)
	if err := dec.Decode(&cfg); err != nil {
		return Config{}, err
	}
    // Basic validation for upstreams
    seen := map[string]struct{}{}
    for _, u := range cfg.Upstreams {
        if u.Name == "" || u.Type == "" {
            return Config{}, errors.New("each upstream requires name and type")
        }
        switch u.Type {
        case "http", "streamable", "http-streamable":
            if u.URL == "" {
                return Config{}, fmt.Errorf("upstream %q of type %q requires url", u.Name, u.Type)
            }
        case "stdio":
            if u.Command == "" {
                return Config{}, fmt.Errorf("upstream %q of type %q requires command", u.Name, u.Type)
            }
        default:
            return Config{}, fmt.Errorf("unsupported upstream type %q for %q", u.Type, u.Name)
        }
        if _, dup := seen[u.Name]; dup {
            return Config{}, fmt.Errorf("duplicate upstream name in config: %s", u.Name)
        }
        seen[u.Name] = struct{}{}
    }
    // Basic validation for identities
    idByName := map[string]struct{}{}
    for _, id := range cfg.Identities {
        if id.Name == "" || id.Type == "" {
            return Config{}, errors.New("each identity requires name and type")
        }
        if _, dup := idByName[id.Name]; dup {
            return Config{}, fmt.Errorf("duplicate identity name in config: %s", id.Name)
        }
        idByName[id.Name] = struct{}{}
        if (id.Type == "service-account" || id.Type == "service_account") && id.APIKey == "" {
            return Config{}, fmt.Errorf("identity %q of type %q requires apiKey", id.Name, id.Type)
        }
        if id.Type == "user" && id.Provider == "" {
            return Config{}, fmt.Errorf("identity %q of type user requires provider", id.Name)
        }
    }
    // Providers validation
    provByName := map[string]struct{}{}
    for _, p := range cfg.Providers {
        if p.Name == "" || p.Mode == "" {
            return Config{}, errors.New("each provider requires name and mode")
        }
        if _, dup := provByName[p.Name]; dup {
            return Config{}, fmt.Errorf("duplicate provider name in config: %s", p.Name)
        }
        provByName[p.Name] = struct{}{}
        if p.Mode == "oidc" {
            if p.JWKSURL == "" || len(p.Audience) == 0 {
                return Config{}, fmt.Errorf("provider %q (oidc) requires jwksUrl and audience", p.Name)
            }
        }
    }
    return cfg, nil
}

// IdentityConfig represents an identity that may authenticate to the gateway.
type IdentityConfig struct {
    Name   string `json:"name"`
    Type   string `json:"type"`   // e.g. "service-account"
    APIKey string `json:"apiKey"` // for service-account
    // For Type=="user": authenticate via OAuth provider
    Provider string `json:"provider,omitempty"`
}

// OAuthProviderConfig defines an OAuth/OIDC provider used to authenticate user identities.
// Two modes are supported initially:
//  - pomerium: trust identity headers from a reverse proxy like Pomerium
//  - oidc: (planned) verify bearer JWT via OIDC JWKS (not yet implemented)
type OAuthProviderConfig struct {
    Name   string `json:"name"`
    Mode   string `json:"mode"` // "pomerium" | "oidc" (oidc TBD)
    // Pomerium header mapping
    HeaderUser        string `json:"headerUser,omitempty"`        // default: X-Authenticated-User-Email
    HeaderAuthenticated string `json:"headerAuthenticated,omitempty"` // default: X-Pomerium-Authenticated
    // Resource metadata URL for WWW-Authenticate hints (RFC 9728)
    ResourceMetadataURL string `json:"resourceMetadataUrl,omitempty"`
    // OIDC parameters (required for mode==oidc)
    JWKSURL   string   `json:"jwksUrl,omitempty"`
    Audience  []string `json:"audience,omitempty"`
    EmailClaim string  `json:"emailClaim,omitempty"`
}

type providerStore struct {
    byName map[string]OAuthProviderConfig
    oidc   map[string]*oidcVerifier
}

func newProviderStore(ps []OAuthProviderConfig) *providerStore {
    m := make(map[string]OAuthProviderConfig)
    oidc := make(map[string]*oidcVerifier)
    for _, p := range ps {
        if p.HeaderUser == "" { p.HeaderUser = "X-Authenticated-User-Email" }
        if p.HeaderAuthenticated == "" { p.HeaderAuthenticated = "X-Pomerium-Authenticated" }
        if p.EmailClaim == "" { p.EmailClaim = "email" }
        m[p.Name] = p
        if p.Mode == "oidc" && p.JWKSURL != "" && len(p.Audience) > 0 {
            oidc[p.Name] = &oidcVerifier{jwksURL: p.JWKSURL, aud: p.Audience, emailClaim: p.EmailClaim, ttl: 5 * time.Minute}
        }
    }
    return &providerStore{byName: m, oidc: oidc}
}

// Minimal OIDC verifier using JWKS and RS256.
type oidcVerifier struct {
    jwksURL    string
    aud        []string
    emailClaim string
    ttl        time.Duration

    mu        sync.Mutex
    keys      map[string]*rsa.PublicKey // kid -> key
    fetchedAt time.Time
}

func (v *oidcVerifier) verifyToken(tokenStr string) (email string, exp time.Time, err error) {
    // Lazy refresh keys
    keyfunc := func(t *jwt.Token) (any, error) {
        if t.Method.Alg() != "RS256" && !strings.HasPrefix(t.Method.Alg(), "RS") {
            return nil, fmt.Errorf("unsupported alg %s", t.Method.Alg())
        }
        kid, _ := t.Header["kid"].(string)
        k := v.getKey(kid)
        if k == nil {
            if err := v.refresh(); err != nil {
                return nil, err
            }
            k = v.getKey(kid)
        }
        if k == nil {
            return nil, fmt.Errorf("unknown key id")
        }
        return k, nil
    }
    var claims jwt.MapClaims
    tok, err := jwt.ParseWithClaims(tokenStr, jwt.MapClaims{}, keyfunc)
    if err != nil || !tok.Valid {
        return "", time.Time{}, fmt.Errorf("invalid token: %w", err)
    }
    claims, _ = tok.Claims.(jwt.MapClaims)
    // audience check
    if audRaw, ok := claims["aud"]; ok {
        okAud := false
        switch vv := audRaw.(type) {
        case string:
            for _, a := range v.aud { if vv == a { okAud = true; break } }
        case []any:
            for _, x := range vv {
                if s, ok := x.(string); ok {
                    for _, a := range v.aud { if s == a { okAud = true; break } }
                }
            }
        }
        if !okAud { return "", time.Time{}, fmt.Errorf("aud mismatch") }
    }
    // expiration
    if expRaw, ok := claims["exp"]; ok {
        switch n := expRaw.(type) {
        case float64:
            exp = time.Unix(int64(n), 0)
        case json.Number:
            if i, _ := n.Int64(); i > 0 { exp = time.Unix(i, 0) }
        }
    }
    if exp.IsZero() || time.Now().After(exp) { return "", time.Time{}, fmt.Errorf("expired") }
    // email
    if e, ok := claims[v.emailClaim].(string); ok && e != "" {
        return e, exp, nil
    }
    return "", time.Time{}, fmt.Errorf("email claim missing")
}

func (v *oidcVerifier) getKey(kid string) *rsa.PublicKey {
    v.mu.Lock(); defer v.mu.Unlock()
    if v.keys == nil { return nil }
    return v.keys[kid]
}

func (v *oidcVerifier) refresh() error {
    v.mu.Lock()
    if time.Since(v.fetchedAt) < v.ttl && v.keys != nil {
        v.mu.Unlock()
        return nil
    }
    v.mu.Unlock()
    resp, err := http.Get(v.jwksURL)
    if err != nil { return err }
    defer resp.Body.Close()
    var jwks struct { Keys []struct{ Kty, Kid, N, E string } `json:"keys"` }
    if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil { return err }
    m := make(map[string]*rsa.PublicKey)
    for _, k := range jwks.Keys {
        if k.Kty != "RSA" { continue }
        nBytes, err := base64.RawURLEncoding.DecodeString(k.N)
        if err != nil { continue }
        eBytes, err := base64.RawURLEncoding.DecodeString(k.E)
        if err != nil { continue }
        var eInt int
        for _, b := range eBytes { eInt = eInt<<8 | int(b) }
        key := &rsa.PublicKey{N: new(big.Int).SetBytes(nBytes), E: eInt}
        m[k.Kid] = key
    }
    v.mu.Lock()
    v.keys = m
    v.fetchedAt = time.Now()
    v.mu.Unlock()
    return nil
}

type identityStore struct {
    byAPIKey map[string]IdentityConfig
    byName   map[string]IdentityConfig
}

func newIdentityStore(ids []IdentityConfig) (*identityStore, error) {
    s := &identityStore{byAPIKey: make(map[string]IdentityConfig), byName: make(map[string]IdentityConfig)}
    for _, id := range ids {
        switch id.Type {
        case "service-account", "service_account":
            if id.APIKey == "" {
                return nil, fmt.Errorf("identity %q of type %q requires apiKey", id.Name, id.Type)
            }
            if _, exists := s.byAPIKey[id.APIKey]; exists {
                return nil, fmt.Errorf("duplicate apiKey in identities (identity %q)", id.Name)
            }
            s.byAPIKey[id.APIKey] = id
            s.byName[id.Name] = id
        case "user":
            if id.Provider == "" {
                return nil, fmt.Errorf("identity %q type user requires provider", id.Name)
            }
            s.byName[id.Name] = id
        default:
            return nil, fmt.Errorf("unsupported identity type %q for %q", id.Type, id.Name)
        }
    }
    return s, nil
}

// authenticate checks Authorization: Bearer <token> or X-API-Key headers.
func (s *identityStore) authenticate(r *http.Request) (IdentityConfig, bool) {
    // Authorization: Bearer <token>
    if auth := r.Header.Get("Authorization"); auth != "" {
        const prefix = "Bearer "
        if len(auth) > len(prefix) && auth[:len(prefix)] == prefix {
            if id, ok := s.byAPIKey[auth[len(prefix):]]; ok {
                return id, true
            }
        }
    }
    // X-API-Key: <token>
    if key := r.Header.Get("X-API-Key"); key != "" {
        if id, ok := s.byAPIKey[key]; ok {
            return id, true
        }
    }
    return IdentityConfig{}, false
}

// policy configuration and enforcement
type PolicyConfig struct {
    Name       string                         `json:"name"`
    Identities []string                       `json:"identities"`
    Upstreams  map[string]PolicyUpstreamScope `json:"upstreams"`
}

type PolicyUpstreamScope struct {
    Tools []string `json:"tools,omitempty"` // omit/empty or ["*"] => all
}

type policyStore struct {
    // identity -> upstream -> allowed tool set (nil means all tools via policy)
    allowed map[string]map[string]map[string]struct{}
}

func newPolicyStore(cfgPolicies []PolicyConfig, ids *identityStore, mgr *manager) (*policyStore, error) {
    ps := &policyStore{allowed: make(map[string]map[string]map[string]struct{})}
    // Validate references
    upstreamExists := func(name string) bool {
        mgr.mu.Lock()
        defer mgr.mu.Unlock()
        _, ok := mgr.upstreams[name]
        return ok
    }
    for _, p := range cfgPolicies {
        if p.Name == "" {
            return nil, fmt.Errorf("policy requires name")
        }
        if len(p.Identities) == 0 || len(p.Upstreams) == 0 {
            return nil, fmt.Errorf("policy %q requires at least one identity and one upstream", p.Name)
        }
        // Validate identities
        for _, ident := range p.Identities {
            if _, ok := ids.byName[ident]; !ok {
                return nil, fmt.Errorf("policy %q references unknown identity %q", p.Name, ident)
            }
        }
        // Validate upstreams
        for upName := range p.Upstreams {
            if !upstreamExists(upName) {
                return nil, fmt.Errorf("policy %q references unknown upstream %q", p.Name, upName)
            }
        }
        // Expand to identity x upstream matrix, optionally restricting tools per upstream
        for _, ident := range p.Identities {
            if ps.allowed[ident] == nil { ps.allowed[ident] = make(map[string]map[string]struct{}) }
            for upName, upCfg := range p.Upstreams {
                // If no tools listed or ["*"], allow all tools for this upstream.
                allowAll := false
                if upCfg.Tools == nil || len(upCfg.Tools) == 0 || (len(upCfg.Tools) == 1 && upCfg.Tools[0] == "*") {
                    allowAll = true
                }
                existing := ps.allowed[ident][upName]
                if allowAll {
                    // Any policy granting all tools overrides prior restrictions.
                    ps.allowed[ident][upName] = nil
                    continue
                }
                if existing == nil {
                    existing = make(map[string]struct{})
                }
                for _, t := range upCfg.Tools {
                    existing[t] = struct{}{}
                }
                ps.allowed[ident][upName] = existing
            }
        }
    }
    return ps, nil
}

func (ps *policyStore) Allowed(identity, upstream, tool string) bool {
    if ps == nil { return false }
    up := ps.allowed[identity]
    if up == nil { return false }
    tools, ok := up[upstream]
    if !ok { return false }
    if tools == nil { return true }
    _, ok = tools[tool]
    return ok
}

// identity context
type ctxKey string
const identityKey ctxKey = "identity"

// authMiddleware enforces that an identity is present and valid.
func authMiddleware(next http.Handler, store *identityStore, providers *providerStore, resourceMetaURL string) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        if store == nil {
            next.ServeHTTP(w, r)
            return
        }
        // 1) Service-account API key auth
        if id, ok := store.authenticate(r); ok {
            next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), identityKey, id)))
            return
        }

        // 2) OAuth2 user auth via providers
        // Try Pomerium-style headers first based on configured providers
        if providers != nil {
            // Iterate identities of type user and see if a provider header matches
            for _, id := range store.byName {
                if id.Type != "user" || id.Provider == "" { continue }
                p, ok := providers.byName[id.Provider]
                if !ok { continue }
                switch p.Mode {
                case "pomerium":
                    user := r.Header.Get(p.HeaderUser)
                    authed := r.Header.Get(p.HeaderAuthenticated)
                    if user != "" && (strings.ToLower(authed) == "true" || authed == "1" || authed == "") {
                        // Match the configured identity by Name (e.g., email)
                        if strings.EqualFold(user, id.Name) {
                            next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), identityKey, id)))
                            return
                        }
                    }
                case "oidc":
                    // Expect bearer token
                    authz := r.Header.Get("Authorization")
                    parts := strings.Fields(authz)
                    if len(parts) == 2 && strings.ToLower(parts[0]) == "bearer" {
                        if v := providers.oidc[id.Provider]; v != nil {
                            email, _, err := v.verifyToken(parts[1])
                            if err == nil && strings.EqualFold(email, id.Name) {
                                next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), identityKey, id)))
                                return
                            }
                        }
                    }
                }
            }
        }

        if resourceMetaURL != "" {
            w.Header().Set("WWW-Authenticate", "Bearer resource_metadata="+resourceMetaURL)
        } else {
            w.Header().Set("WWW-Authenticate", "Bearer")
        }
        http.Error(w, "Unauthorized", http.StatusUnauthorized)
    })
}

// auditMiddleware logs tool call attempts with identity and allow/deny evaluation
// based on policies and upstream allowlists. It logs attempts before passing the
// request to the underlying handler. Actual execution results are logged by
// per-tool wrappers in the session server.
func auditMiddleware(next http.Handler, store *identityStore, policies *policyStore, mgr *manager) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        // Only inspect client->server messages (POST)
        if r.Method == http.MethodPost {
            val := r.Context().Value(identityKey)
            id, _ := val.(IdentityConfig)

            // Read and restore body
            data, _ := io.ReadAll(r.Body)
            _ = r.Body.Close()
            r.Body = io.NopCloser(bytes.NewReader(data))

            // Minimal JSON-RPC request parsing
            var envelope struct {
                Method string          `json:"method"`
                Params json.RawMessage `json:"params"`
            }
            if err := json.Unmarshal(data, &envelope); err == nil && envelope.Method == "tools/call" {
                var params struct {
                    Name string `json:"name"`
                }
                if err := json.Unmarshal(envelope.Params, &params); err == nil {
                    // Determine upstream/tool from namespaced name "/<upstream>/<tool>"
                    upstream, tool := parseNamespacedTool(params.Name)
                    allowed := false
                    if upstream == "" { // static gateway tools
                        allowed = id.Name != ""
                    } else {
                        // Check policy and upstream allowlist
                        if id.Name != "" && policies != nil && policies.Allowed(id.Name, upstream, tool) {
                            mgr.mu.Lock()
                            up := mgr.upstreams[upstream]
                            mgr.mu.Unlock()
                            if up != nil {
                                if up.allowedTools == nil {
                                    allowed = true
                                } else {
                                    _, allowed = up.allowedTools[tool]
                                }
                            }
                        }
                    }
                    log.Printf("audit attempt identity=%q upstream=%q tool=%q allowed=%t", id.Name, upstream, tool, allowed)
                }
            }

            // restore again to be safe if handler reads twice
            r.Body = io.NopCloser(bytes.NewReader(data))
        }
        next.ServeHTTP(w, r)
    })
}

func parseNamespacedTool(name string) (upstream, tool string) {
    if name == "" || name[0] != '/' {
        return "", name
    }
    // Expect "/upstream/tool"
    parts := strings.SplitN(name[1:], "/", 2)
    if len(parts) != 2 {
        return "", name
    }
    return parts[0], parts[1]
}

func main() {
	addr := flag.String("addr", ":8080", "address to listen on (host:port)")
	cfgPath := flag.String("config", "gateway.json", "path to JSON config with upstreams")
	flag.Parse()

    // Load upstreams and connect
    cfg, err := loadConfig(*cfgPath)
    if err != nil {
        log.Fatalf("failed to load config: %v", err)
    }
    mgr := newManager()
    if len(cfg.Upstreams) > 0 {
        ctx := context.Background()
        for _, u := range cfg.Upstreams {
            if err := mgr.addUpstream(ctx, u); err != nil {
                log.Printf("failed to add upstream %s: %v", u.Name, err)
            } else {
                log.Printf("connected upstream: %s (%s)", u.Name, u.URL)
            }
        }
    }

    // Build policy store (deny by default; explicit allow via policy)
    // Create identity and provider stores first.
    store, err := newIdentityStore(cfg.Identities)
    if err != nil {
        log.Fatalf("invalid identities: %v", err)
    }
    providers := newProviderStore(cfg.Providers)
    policies, err := newPolicyStore(cfg.Policies, store, mgr)
    if err != nil {
        log.Fatalf("invalid policies: %v", err)
    }

    // Expose the server over HTTP using the streamable transport, building
    // a per-request server filtered by identity + policies.
    baseHandler := mcp.NewStreamableHTTPHandler(func(req *http.Request) *mcp.Server {
        val := req.Context().Value(identityKey)
        id, _ := val.(IdentityConfig)
        // Create a new server for this session/request
        server := mcp.NewServer(&mcp.Implementation{
            Name:    "mcp-gateway",
            Version: "0.3.0",
        }, &mcp.ServerOptions{HasTools: true})

        // Add static tools (always available to authenticated identities) with audit logs
        mcp.AddTool(server, &mcp.Tool{
            Name:        "gateway.info",
            Title:       "Gateway Info",
            Description: "Return basic information about the MCP gateway",
        }, func(ctx context.Context, req *mcp.CallToolRequest, in emptyArgs) (*mcp.CallToolResult, any, error) {
            start := time.Now()
            res, out, err := infoHandler(ctx, req, in)
            success := err == nil && (res == nil || !res.IsError)
            dur := time.Since(start)
            if err != nil {
                log.Printf("audit result identity=%q upstream=%q tool=%q success=%t duration_ms=%d error=%v", id.Name, "", "gateway.info", success, dur.Milliseconds(), err)
            } else {
                log.Printf("audit result identity=%q upstream=%q tool=%q success=%t duration_ms=%d", id.Name, "", "gateway.info", success, dur.Milliseconds())
            }
            return res, out, err
        })
        mcp.AddTool(server, &mcp.Tool{
            Name:        "gateway.proxy",
            Title:       "Gateway Proxy",
            Description: "Proxy a request via the gateway (not implemented yet)",
        }, func(ctx context.Context, req *mcp.CallToolRequest, in proxyArgs) (*mcp.CallToolResult, any, error) {
            start := time.Now()
            res, out, err := proxyHandler(ctx, req, in)
            success := err == nil && (res == nil || !res.IsError)
            dur := time.Since(start)
            if err != nil {
                log.Printf("audit result identity=%q upstream=%q tool=%q success=%t duration_ms=%d error=%v", id.Name, "", "gateway.proxy", success, dur.Milliseconds(), err)
            } else {
                log.Printf("audit result identity=%q upstream=%q tool=%q success=%t duration_ms=%d", id.Name, "", "gateway.proxy", success, dur.Milliseconds())
            }
            return res, out, err
        })

        // Add upstream tools allowed by policies and upstream tool allowlists
        mgr.mu.Lock()
        for upName, up := range mgr.upstreams {
            for origName, entry := range up.entries {
                if id.Name == "" || !policies.Allowed(id.Name, upName, origName) {
                    continue
                }
                if up.allowedTools != nil {
                    if _, ok := up.allowedTools[origName]; !ok {
                        continue
                    }
                }
                toolCopy := *entry.upstreamTool
                toolCopy.Name = "/" + upName + "/" + origName
                // Wrap handler to log result
                wrapped := func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
                    start := time.Now()
                    res, err := entry.handler(ctx, req)
                    success := err == nil && (res == nil || !res.IsError)
                    dur := time.Since(start)
                    if err != nil {
                        log.Printf("audit result identity=%q upstream=%q tool=%q success=%t duration_ms=%d error=%v", id.Name, upName, origName, success, dur.Milliseconds(), err)
                    } else {
                        log.Printf("audit result identity=%q upstream=%q tool=%q success=%t duration_ms=%d", id.Name, upName, origName, success, dur.Milliseconds())
                    }
                    return res, err
                }
                server.AddTool(&toolCopy, wrapped)
            }
        }
        mgr.mu.Unlock()
        return server
    }, nil)
    var handler http.Handler = baseHandler
    // Ensure identity is set before auditing by placing auth outermost.
    handler = auditMiddleware(handler, store, policies, mgr)
    // Provide a (single) resource metadata URL if any provider specifies it.
    resourceMetaURL := ""
    for _, p := range providers.byName { if p.ResourceMetadataURL != "" { resourceMetaURL = p.ResourceMetadataURL; break } }
    handler = authMiddleware(handler, store, providers, resourceMetaURL)

	log.Printf("mcp-gateway listening on %s", *addr)
    if err := http.ListenAndServe(*addr, handler); err != nil {
        log.Fatal(fmt.Errorf("listen and serve: %w", err))
    }
}
