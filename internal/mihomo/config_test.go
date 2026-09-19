package mihomo

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/underhax/mihomo-warp-proxy/internal/config"
	"github.com/underhax/mihomo-warp-proxy/internal/logging"
	"github.com/underhax/mihomo-warp-proxy/internal/wgcf"
)

var (
	testProfile = &wgcf.Profile{
		PrivateKey: "YH2h2kSHzMaAgBNiNWuMEljlKGsaVKnv+hFtZOZEEEE=",
		PublicKey:  "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=",
		IPv4:       "172.16.0.2",
		IPv6:       "2606:4700:110:8949:fed8:548c:4603:5b00",
	}
	testReserved = [3]byte{1, 2, 3}
	testLog      = logging.New(logging.LevelDebug, "test")
)

func testConfig(dir string) *config.Config {
	return &config.Config{
		ProxyPort:     7890,
		ProxyLogLevel: "info",
		ProxyUser:     "user",
		ProxyPass:     "pass",
		UseIP6:        true,
		Geo: config.GeoConfig{
			Enabled: true,
			URLs: config.GeoURLs{
				GeoIP:   "https://example.com/geoip.dat",
				GeoSite: "https://example.com/geosite.dat",
				MMDB:    "https://example.com/geoip.metadb",
				ASN:     "https://example.com/GeoLite2-ASN.mmdb",
			},
		},
		Warp: config.WarpConfig{
			Enabled:  true,
			Endpoint: "engage.cloudflareclient.com:2408",
			DNS:      []string{"1.1.1.1", "1.0.0.1"},
		},
		Paths: config.Paths{
			MihomoConfigFile: filepath.Join(dir, "config.yaml"),
			MihomoData:       dir,
		},
	}
}

func getSlice(t *testing.T, m map[string]any, key string) []any {
	t.Helper()
	val, ok := m[key]
	if !ok {
		t.Fatalf("key %q not found in document", key)
	}
	s, ok := val.([]any)
	if !ok {
		t.Fatalf("key %q is not []any, got %T", key, val)
	}
	return s
}

func getString(t *testing.T, val any) string {
	t.Helper()
	s, ok := val.(string)
	if !ok {
		t.Fatalf("value is not string, got %T", val)
	}
	return s
}

func getMap(t *testing.T, val any) map[string]any {
	t.Helper()
	m, ok := val.(map[string]any)
	if !ok {
		t.Fatalf("value is not map[string]any, got %T", val)
	}
	return m
}

func hasProxy(proxies []any, name string) bool {
	for _, p := range proxies {
		if m, ok := p.(map[string]any); ok {
			if n, ok := m["name"].(string); ok && n == name {
				return true
			}
		}
	}
	return false
}

func readYAML(t *testing.T, path string) map[string]any {
	t.Helper()
	cleanPath := filepath.Clean(path)
	data, err := os.ReadFile(cleanPath)
	if err != nil {
		t.Fatalf("readYAML: %v", err)
	}
	doc := make(map[string]any)
	if err := yaml.Unmarshal(data, &doc); err != nil {
		t.Fatalf("readYAML unmarshal: %v", err)
	}
	return doc
}

func TestEnsureConfigCreatesTemplate(t *testing.T) {
	dir := t.TempDir()
	cfg := testConfig(dir)

	if err := EnsureConfig(cfg, testProfile, testReserved, testLog); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	doc := readYAML(t, cfg.Paths.MihomoConfigFile)

	if doc["mixed-port"] == nil {
		t.Error("mixed-port missing from created config")
	}
	if doc["authentication"] == nil {
		t.Error("authentication missing from created config")
	}
	if doc["proxies"] == nil {
		t.Error("proxies missing from created config")
	}
	if doc["rules"] == nil {
		t.Error("rules missing from created config")
	}
}

func TestTemplateRulesWarp(t *testing.T) {
	dir := t.TempDir()
	cfg := testConfig(dir)
	cfg.Warp.Enabled = true

	if err := EnsureConfig(cfg, testProfile, testReserved, testLog); err != nil {
		t.Fatal(err)
	}

	doc := readYAML(t, cfg.Paths.MihomoConfigFile)
	rules := getSlice(t, doc, "rules")
	if len(rules) != 1 || getString(t, rules[0]) != minimalTemplateWarpRule() {
		t.Errorf("template rules: got %v, want [%s]", rules, minimalTemplateWarpRule())
	}
}

func TestTemplateRulesDirect(t *testing.T) {
	dir := t.TempDir()
	cfg := testConfig(dir)
	cfg.Warp.Enabled = false

	if err := EnsureConfig(cfg, nil, [3]byte{}, testLog); err != nil {
		t.Fatal(err)
	}

	doc := readYAML(t, cfg.Paths.MihomoConfigFile)
	rules := getSlice(t, doc, "rules")
	if len(rules) != 1 || getString(t, rules[0]) != minimalTemplateDirectRule() {
		t.Errorf("template rules: got %v, want [%s]", rules, minimalTemplateDirectRule())
	}
}

func TestEnsureConfigFilePermissions(t *testing.T) {
	dir := t.TempDir()
	cfg := testConfig(dir)

	if err := EnsureConfig(cfg, testProfile, testReserved, testLog); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	info, err := os.Stat(cfg.Paths.MihomoConfigFile)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("config file permissions: got %04o, want 0o600", perm)
	}
}

func TestPatchOverwritesOwnedFields(t *testing.T) {
	dir := t.TempDir()
	cfg := testConfig(dir)

	if err := EnsureConfig(cfg, testProfile, testReserved, testLog); err != nil {
		t.Fatal(err)
	}

	cfg.ProxyPort = 8080
	cfg.ProxyLogLevel = "debug"
	cfg.UseIP6 = false

	if err := EnsureConfig(cfg, testProfile, testReserved, testLog); err != nil {
		t.Fatal(err)
	}

	doc := readYAML(t, cfg.Paths.MihomoConfigFile)

	if port, ok := doc["mixed-port"].(int); !ok || port != 8080 {
		t.Errorf("mixed-port not updated: got %v", doc["mixed-port"])
	}
	if level, ok := doc["log-level"].(string); !ok || level != "debug" {
		t.Errorf("log-level not updated: got %v", doc["log-level"])
	}
	if ipv6, ok := doc["ipv6"].(bool); !ok || ipv6 != false {
		t.Errorf("ipv6 not updated: got %v", doc["ipv6"])
	}
}

func TestPatchPreservesUserKeys(t *testing.T) {
	dir := t.TempDir()
	cfg := testConfig(dir)

	userConfig := `
mixed-port: 7890
log-level: info
ipv6: true
allow-lan: true
bind-address: "*"
authentication:
  - "user:pass"
listeners:
  - name: socks-in
    type: socks
    port: 1080
proxy-groups:
  - name: MyGroup
    type: select
    proxies:
      - warp
      - DIRECT
proxies:
  - name: warp
    type: wireguard
    server: engage.cloudflareclient.com
    port: 2408
    ip: 172.16.0.2
    ipv6: "2606:4700::1"
    public-key: "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo="
    private-key: "YH2h2kSHzMaAgBNiNWuMEljlKGsaVKnv+hFtZOZEEEE="
    udp: true
    mtu: 1280
    dns:
      - 1.1.1.1
rules:
  - DOMAIN-SUFFIX,preserve.example.com,DIRECT
  - MATCH,PreserveGroup
`
	if err := os.WriteFile(cfg.Paths.MihomoConfigFile, []byte(userConfig), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := EnsureConfig(cfg, testProfile, testReserved, testLog); err != nil {
		t.Fatal(err)
	}

	doc := readYAML(t, cfg.Paths.MihomoConfigFile)

	listeners, ok := doc["listeners"].([]any)
	if !ok || len(listeners) == 0 {
		t.Error("user-defined listeners were removed")
	}

	groups, ok := doc["proxy-groups"].([]any)
	if !ok || len(groups) == 0 {
		t.Error("user-defined proxy-groups were removed")
	}

	rules := getSlice(t, doc, "rules")
	if len(rules) != 2 {
		t.Errorf("rules count changed: got %d, want 2", len(rules))
	}
	if getString(t, rules[0]) != "DOMAIN-SUFFIX,preserve.example.com,DIRECT" {
		t.Errorf("user rule[0] changed: got %q", rules[0])
	}
	if getString(t, rules[1]) != "MATCH,PreserveGroup" {
		t.Errorf("user rule[1] changed: got %q", rules[1])
	}
}

func TestPatchAppendsWarpWhenMissingWithOtherProxies(t *testing.T) {
	dir := t.TempDir()
	cfg := testConfig(dir)

	userConfig := `
mixed-port: 7890
log-level: info
ipv6: true
allow-lan: true
bind-address: "*"
authentication: []
proxies:
  - name: my-vless
    type: vless
    server: example.com
    port: 443
rules:
  - DOMAIN-SUFFIX,append.example.com,DIRECT
  - MATCH,my-vless
`
	if err := os.WriteFile(cfg.Paths.MihomoConfigFile, []byte(userConfig), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := EnsureConfig(cfg, testProfile, testReserved, testLog); err != nil {
		t.Fatal(err)
	}

	doc := readYAML(t, cfg.Paths.MihomoConfigFile)

	proxies := getSlice(t, doc, "proxies")
	if len(proxies) != 2 {
		t.Fatalf("expected 2 proxies, got %d", len(proxies))
	}

	if !hasProxy(proxies, "warp") {
		t.Error("warp proxy was not appended")
	}
	if !hasProxy(proxies, "my-vless") {
		t.Error("my-vless proxy was removed")
	}

	rules := getSlice(t, doc, "rules")
	if len(rules) != 2 {
		t.Fatalf("rules count changed: got %d, want 2", len(rules))
	}
	if getString(t, rules[1]) != "MATCH,my-vless" {
		t.Errorf("rules[1] changed: got %q", rules[1])
	}
}

func TestPatchReplacesMatchDirectWhenMinimalTemplate(t *testing.T) {
	dir := t.TempDir()
	cfg := testConfig(dir)
	cfg.Warp.Enabled = false

	if err := EnsureConfig(cfg, nil, [3]byte{}, testLog); err != nil {
		t.Fatal(err)
	}

	cfg.Warp.Enabled = true
	if err := EnsureConfig(cfg, testProfile, testReserved, testLog); err != nil {
		t.Fatal(err)
	}

	doc := readYAML(t, cfg.Paths.MihomoConfigFile)
	rules := getSlice(t, doc, "rules")
	if len(rules) != 1 || getString(t, rules[0]) != minimalTemplateWarpRule() {
		t.Errorf("rules: got %v, want [%s]", rules, minimalTemplateWarpRule())
	}
	proxies := getSlice(t, doc, "proxies")
	if !hasProxy(proxies, "warp") {
		t.Error("warp proxy not added")
	}
}

func TestPatchDoesNotReplaceMatchDirectWhenUserHasCustomRules(t *testing.T) {
	dir := t.TempDir()
	cfg := testConfig(dir)

	userConfig := `
mixed-port: 7890
log-level: info
ipv6: true
allow-lan: true
bind-address: "*"
authentication: []
proxies: []
rules:
  - DOMAIN-SUFFIX,custom.example.com,DIRECT
  - MATCH,DIRECT
`
	if err := os.WriteFile(cfg.Paths.MihomoConfigFile, []byte(userConfig), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := EnsureConfig(cfg, testProfile, testReserved, testLog); err != nil {
		t.Fatal(err)
	}

	doc := readYAML(t, cfg.Paths.MihomoConfigFile)
	rules := getSlice(t, doc, "rules")
	if len(rules) != 2 {
		t.Fatalf("rules count changed: got %d, want 2", len(rules))
	}
	if getString(t, rules[1]) != minimalTemplateDirectRule() {
		t.Errorf("rules[1] changed: got %q", rules[1])
	}
}

func TestPatchDoesNotModifyRules(t *testing.T) {
	dir := t.TempDir()
	cfg := testConfig(dir)

	if err := EnsureConfig(cfg, testProfile, testReserved, testLog); err != nil {
		t.Fatal(err)
	}

	doc := readYAML(t, cfg.Paths.MihomoConfigFile)
	doc["rules"] = []any{
		"DOMAIN-SUFFIX,audit.example.com,DIRECT",
		"GEOIP,CN,DIRECT",
		"MATCH,AuditGroup",
	}
	data, err := yaml.Marshal(doc)
	if err != nil {
		t.Fatalf("yaml.Marshal: %v", err)
	}
	if err := os.WriteFile(cfg.Paths.MihomoConfigFile, data, 0o600); err != nil {
		t.Fatal(err)
	}

	if err := EnsureConfig(cfg, testProfile, testReserved, testLog); err != nil {
		t.Fatal(err)
	}

	doc = readYAML(t, cfg.Paths.MihomoConfigFile)
	rules := getSlice(t, doc, "rules")

	if len(rules) != 3 {
		t.Fatalf("rules count changed: got %d, want 3", len(rules))
	}
	if getString(t, rules[0]) != "DOMAIN-SUFFIX,audit.example.com,DIRECT" {
		t.Errorf("rules[0] changed: got %q", rules[0])
	}
	if getString(t, rules[1]) != "GEOIP,CN,DIRECT" {
		t.Errorf("rules[1] changed: got %q", rules[1])
	}
	if getString(t, rules[2]) != "MATCH,AuditGroup" {
		t.Errorf("rules[2] changed: got %q", rules[2])
	}
}

func TestReservedWrittenWhenNonZero(t *testing.T) {
	dir := t.TempDir()
	cfg := testConfig(dir)

	if err := EnsureConfig(cfg, testProfile, [3]byte{10, 20, 30}, testLog); err != nil {
		t.Fatal(err)
	}

	doc := readYAML(t, cfg.Paths.MihomoConfigFile)
	proxies := getSlice(t, doc, "proxies")
	proxy := getMap(t, proxies[0])

	if proxy["reserved"] == nil {
		t.Error("reserved not written when non-zero")
	}
}

func TestReservedNotWrittenWhenZero(t *testing.T) {
	dir := t.TempDir()
	cfg := testConfig(dir)

	if err := EnsureConfig(cfg, testProfile, [3]byte{0, 0, 0}, testLog); err != nil {
		t.Fatal(err)
	}

	doc := readYAML(t, cfg.Paths.MihomoConfigFile)
	proxies := getSlice(t, doc, "proxies")
	proxy := getMap(t, proxies[0])

	if proxy["reserved"] != nil {
		t.Errorf("reserved written for zero value: %v", proxy["reserved"])
	}
}

func TestGeoBlockRemovedWhenDisabled(t *testing.T) {
	dir := t.TempDir()
	cfg := testConfig(dir)
	cfg.Geo.Enabled = true

	if err := EnsureConfig(cfg, testProfile, testReserved, testLog); err != nil {
		t.Fatal(err)
	}

	cfg.Geo.Enabled = false
	if err := EnsureConfig(cfg, testProfile, testReserved, testLog); err != nil {
		t.Fatal(err)
	}

	doc := readYAML(t, cfg.Paths.MihomoConfigFile)
	for _, k := range []string{"geodata-mode", "geodata-loader", "geo-auto-update", "geox-url"} {
		if _, exists := doc[k]; exists {
			t.Errorf("geo key %q still present after GEO disabled", k)
		}
	}
}

func TestAmneziaBlockAddedAndRemoved(t *testing.T) {
	dir := t.TempDir()
	cfg := testConfig(dir)
	cfg.Warp.Amnezia = config.AmneziaConfig{
		Enabled: true,
		JC:      5,
		JMin:    7,
		JMax:    15,
		I:       [5]string{"1", "", "3", "", "5"},
	}

	if err := EnsureConfig(cfg, testProfile, testReserved, testLog); err != nil {
		t.Fatal(err)
	}

	doc := readYAML(t, cfg.Paths.MihomoConfigFile)
	proxies := getSlice(t, doc, "proxies")
	proxy := getMap(t, proxies[0])

	if proxy["amnezia-wg-option"] == nil {
		t.Error("amnezia-wg-option not written when Amnezia enabled")
	}

	cfg.Warp.Amnezia.Enabled = false
	if err := EnsureConfig(cfg, testProfile, testReserved, testLog); err != nil {
		t.Fatal(err)
	}

	doc = readYAML(t, cfg.Paths.MihomoConfigFile)
	proxies = getSlice(t, doc, "proxies")
	proxy = getMap(t, proxies[0])

	if proxy["amnezia-wg-option"] != nil {
		t.Error("amnezia-wg-option still present after Amnezia disabled")
	}
}

func TestSplitEndpoint(t *testing.T) {
	cases := []struct {
		input    string
		wantHost string
		wantPort int
	}{
		{"engage.cloudflareclient.com:2408", "engage.cloudflareclient.com", 2408},
		{"engage.cloudflareclient.com:500", "engage.cloudflareclient.com", 500},
		{"host:0", "host", 0},
		{"noport", "noport", 0},
	}

	for _, tc := range cases {
		host, port := splitEndpoint(tc.input)
		if host != tc.wantHost {
			t.Errorf("splitEndpoint(%q) host: got %q, want %q", tc.input, host, tc.wantHost)
		}
		if port != tc.wantPort {
			t.Errorf("splitEndpoint(%q) port: got %d, want %d", tc.input, port, tc.wantPort)
		}
	}
}

func TestFindProxyByNameNode(t *testing.T) {
	makeNode := func(name string) *yaml.Node {
		return &yaml.Node{
			Kind: yaml.MappingNode,
			Tag:  yamlTagMap,
			Content: []*yaml.Node{
				{Kind: yaml.ScalarNode, Tag: yamlTagStr, Value: "name"},
				{Kind: yaml.ScalarNode, Tag: yamlTagStr, Value: name},
			},
		}
	}
	seq := &yaml.Node{
		Kind:    yaml.SequenceNode,
		Tag:     yamlTagSeq,
		Content: []*yaml.Node{makeNode("direct"), makeNode("warp"), makeNode("vless")},
	}

	if idx := findProxyByNameNode(seq, "warp"); idx != 1 {
		t.Errorf("findProxyByNameNode warp: got %d, want 1", idx)
	}
	if idx := findProxyByNameNode(seq, "missing"); idx != -1 {
		t.Errorf("findProxyByNameNode missing: got %d, want -1", idx)
	}
	emptySeq := &yaml.Node{Kind: yaml.SequenceNode, Tag: yamlTagSeq}
	if idx := findProxyByNameNode(emptySeq, "warp"); idx != -1 {
		t.Errorf("findProxyByNameNode empty: got %d, want -1", idx)
	}
}

func TestDocMappingAndYamlNodeNameEdgeCases(t *testing.T) {
	if got := docMapping(&yaml.Node{Kind: yaml.ScalarNode}); got != nil {
		t.Error("expected nil for non-DocumentNode")
	}
	if got := docMapping(&yaml.Node{Kind: yaml.DocumentNode, Content: []*yaml.Node{}}); got != nil {
		t.Error("expected nil for empty DocumentNode")
	}
	if got := docMapping(&yaml.Node{Kind: yaml.DocumentNode, Content: []*yaml.Node{{Kind: yaml.ScalarNode}}}); got != nil {
		t.Error("expected nil for non-Mapping root inside DocumentNode")
	}
	mapNode := &yaml.Node{Kind: yaml.MappingNode}
	if got := docMapping(mapNode); got != mapNode {
		t.Error("expected direct MappingNode to return itself")
	}
	if got := yamlNodeName(nil); got != "" {
		t.Error("expected empty string for nil node")
	}
	if got := yamlNodeName(&yaml.Node{Kind: yaml.ScalarNode}); got != "" {
		t.Error("expected empty string for scalar node")
	}
	nodeWithoutName := &yaml.Node{
		Kind: yaml.MappingNode,
		Content: []*yaml.Node{
			strNode("other"),
			strNode("value"),
		},
	}
	if got := yamlNodeName(nodeWithoutName); got != "" {
		t.Errorf("expected empty string, got %q", got)
	}
	host, port := splitEndpoint("badport.example.com:notaport")
	if host != "badport.example.com" || port != 0 {
		t.Errorf("splitEndpoint with bad port: got %s:%d", host, port)
	}
}

func TestEnsureConfigWriteError(t *testing.T) {
	cfg := &config.Config{
		Paths: config.Paths{
			MihomoConfigFile: "/nonexistent/path/for/config.yaml",
		},
	}
	if err := EnsureConfig(cfg, testProfile, testReserved, testLog); err == nil {
		t.Error("expected error writing to nonexistent path, got nil")
	}
}

func TestPatchConfigOversized(t *testing.T) {
	dir := t.TempDir()
	cfg := testConfig(dir)
	data := bytes.Repeat([]byte("a"), maxConfigSize+10)
	if err := os.WriteFile(cfg.Paths.MihomoConfigFile, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := EnsureConfig(cfg, testProfile, testReserved, testLog); err == nil {
		t.Error("expected error for oversized config, got nil")
	}
}

func TestPatchConfigInvalidYAML(t *testing.T) {
	dir := t.TempDir()
	cfg := testConfig(dir)
	if err := os.WriteFile(cfg.Paths.MihomoConfigFile, []byte("invalid: [yaml:"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := EnsureConfig(cfg, testProfile, testReserved, testLog); err == nil {
		t.Error("expected error for invalid YAML, got nil")
	}
}

func TestPatchConfigNotMapping(t *testing.T) {
	dir := t.TempDir()
	cfg := testConfig(dir)
	if err := os.WriteFile(cfg.Paths.MihomoConfigFile, []byte("- item1\n- item2\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := EnsureConfig(cfg, testProfile, testReserved, testLog); err == nil {
		t.Error("expected error for non-mapping YAML, got nil")
	}
}

func TestEnsureConfigStatError(t *testing.T) {
	dir := t.TempDir()
	dummyFile := filepath.Join(dir, "not_a_directory")
	if err := os.WriteFile(dummyFile, []byte("dummy"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := testConfig(dir)
	cfg.Paths.MihomoConfigFile = filepath.Join(dummyFile, "config.yaml")
	if err := EnsureConfig(cfg, testProfile, testReserved, testLog); err == nil {
		t.Error("expected stat error for invalid path, got nil")
	}
}

func TestWriteConfigErrors(t *testing.T) {
	dir := t.TempDir()
	dummyFile := filepath.Join(dir, "dummy_file")
	if err := os.WriteFile(dummyFile, []byte("data"), 0o600); err != nil {
		t.Fatal(err)
	}
	invalidPath := filepath.Join(dummyFile, "config.yaml")
	if err := writeConfigNode(invalidPath, &yaml.Node{Kind: yaml.MappingNode}); err == nil {
		t.Error("expected writeConfigNode error, got nil")
	}
	if err := writeConfigMap(invalidPath, map[string]any{"test": 1}); err == nil {
		t.Error("expected writeConfigMap error, got nil")
	}
}

func TestIsMinimalTemplateNode(t *testing.T) {
	nonEmptyProxies := &yaml.Node{
		Kind: yaml.MappingNode,
		Content: []*yaml.Node{
			strNode("proxies"),
			{Kind: yaml.SequenceNode, Content: []*yaml.Node{strNode("p1")}},
		},
	}
	if isMinimalTemplateNode(nonEmptyProxies) {
		t.Error("expected false when proxies is not empty")
	}

	noRules := &yaml.Node{
		Kind: yaml.MappingNode,
		Content: []*yaml.Node{
			strNode("proxies"),
			{Kind: yaml.SequenceNode, Content: []*yaml.Node{}},
		},
	}
	if isMinimalTemplateNode(noRules) {
		t.Error("expected false when rules is missing")
	}

	scalarRules := &yaml.Node{
		Kind: yaml.MappingNode,
		Content: []*yaml.Node{
			strNode("rules"),
			strNode("not-a-sequence"),
		},
	}
	if isMinimalTemplateNode(scalarRules) {
		t.Error("expected false when rules is not a sequence")
	}

	twoRules := &yaml.Node{
		Kind: yaml.MappingNode,
		Content: []*yaml.Node{
			strNode("rules"),
			{Kind: yaml.SequenceNode, Content: []*yaml.Node{strNode("MATCH,DIRECT"), strNode("MATCH,warp")}},
		},
	}
	if isMinimalTemplateNode(twoRules) {
		t.Error("expected false when rules length is not 1")
	}

	otherRule := &yaml.Node{
		Kind: yaml.MappingNode,
		Content: []*yaml.Node{
			strNode("rules"),
			{Kind: yaml.SequenceNode, Content: []*yaml.Node{strNode("MATCH,warp")}},
		},
	}
	if isMinimalTemplateNode(otherRule) {
		t.Error("expected false when rule is not MATCH,DIRECT")
	}

	validDirect := &yaml.Node{
		Kind: yaml.MappingNode,
		Content: []*yaml.Node{
			strNode("rules"),
			{Kind: yaml.SequenceNode, Content: []*yaml.Node{strNode(minimalTemplateDirectRule())}},
		},
	}
	if !isMinimalTemplateNode(validDirect) {
		t.Error("expected true for valid minimal template direct rule")
	}
}

func TestPatchConfigOpenError(t *testing.T) {
	cfg := &config.Config{
		Paths: config.Paths{
			MihomoConfigFile: "/nonexistent/config.yaml",
		},
	}
	if err := patchConfig(cfg, testProfile, testReserved, testLog); err == nil {
		t.Error("expected open error, got nil")
	}
}

func TestWriteConfigMarshalErrors(t *testing.T) {
	origMarshal := yamlMarshal
	defer func() { yamlMarshal = origMarshal }()
	yamlMarshal = func(any) ([]byte, error) {
		return nil, errors.New("mock marshal error")
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "cfg.yaml")
	if err := writeConfigNode(path, &yaml.Node{Kind: yaml.MappingNode}); err == nil || !strings.Contains(err.Error(), "marshal config") {
		t.Errorf("expected writeConfigNode marshal error, got: %v", err)
	}
	if err := writeConfigMap(path, map[string]any{"a": 1}); err == nil || !strings.Contains(err.Error(), "marshal config") {
		t.Errorf("expected writeConfigMap marshal error, got: %v", err)
	}
}

func TestPatchConfigFileErrors(t *testing.T) {
	dir := t.TempDir()
	cfg := testConfig(dir)
	if err := os.WriteFile(cfg.Paths.MihomoConfigFile, []byte("port: 7890\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	origClose := fileClose
	defer func() { fileClose = origClose }()
	fileClose = func(*os.File) error {
		return errors.New("mock close error")
	}
	if err := EnsureConfig(cfg, testProfile, testReserved, testLog); err == nil || !strings.Contains(err.Error(), "close config") {
		t.Errorf("expected close config error, got: %v", err)
	}
	fileClose = origClose

	origRead := fileReadAll
	defer func() { fileReadAll = origRead }()
	fileReadAll = func(io.Reader) ([]byte, error) {
		return nil, errors.New("mock read error")
	}
	if err := EnsureConfig(cfg, testProfile, testReserved, testLog); err == nil || !strings.Contains(err.Error(), "read config") {
		t.Errorf("expected read config error, got: %v", err)
	}
}

func TestDefaultHelpers(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "mihomo_helper_test")
	if err != nil {
		t.Fatal(err)
	}
	if closeErr := defaultFileClose(f); closeErr != nil {
		t.Errorf("defaultFileClose failed: %v", closeErr)
	}
	if closeErr := defaultFileClose(f); closeErr == nil {
		t.Error("expected error on double close, got nil")
	}

	b, readErr := defaultFileReadAll(strings.NewReader("content"))
	if readErr != nil || string(b) != "content" {
		t.Errorf("defaultFileReadAll unexpected result: %s, %v", string(b), readErr)
	}
	if _, readFailErr := defaultFileReadAll(errReader{}); readFailErr == nil {
		t.Error("expected error on errReader, got nil")
	}

	data, marshalErr := defaultYAMLMarshal(map[string]string{"key": "val"})
	if marshalErr != nil || len(data) == 0 {
		t.Errorf("defaultYAMLMarshal unexpected result: %s, %v", string(data), marshalErr)
	}
	if _, marshalFailErr := defaultYAMLMarshal(badMarshaler{}); marshalFailErr == nil {
		t.Error("expected error for unmarshalable type, got nil")
	}
}

type badMarshaler struct{}

func (badMarshaler) MarshalYAML() (any, error) {
	return nil, errors.New("custom marshal error")
}

type errReader struct{}

func (errReader) Read(_ []byte) (int, error) {
	return 0, errors.New("simulated read failure")
}
