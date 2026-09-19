// Package mihomo manages the mihomo config.yaml lifecycle.
// The central design constraint is that config.yaml is user-owned: this
// package may only write fields it explicitly declares as its own. Every
// other key — custom listeners, proxy-groups, rule-providers, additional
// proxies, custom rules — must survive a patch cycle unmodified, including
// their original key order.
//
// Owned fields (always overwritten from Config):
//
//	Top-level:  mixed-port, log-level, ipv6, allow-lan, bind-address,
//	            authentication
//	Geo block:  geodata-mode, geodata-loader, geo-auto-update,
//	            geo-update-interval, geox-url.*  (added/removed per GEO flag)
//	proxies[]:  the single entry where .name == "warp" (only when
//	            USE_WARP_CONFIG=true; left untouched otherwise)
//
// rules[] and proxies[] (except the "warp" entry) are only written during
// first-run template creation. On subsequent patch cycles they are never
// touched — the user owns them entirely.
//
// Key order is preserved on patch by using yaml.Node for the full document
// round-trip. map[string]any is used only in createTemplate where there is
// no existing file to preserve.
//
// When USE_WARP_CONFIG=false the entire config is left as-is.
// proxies, rules and all other sections are not touched.
package mihomo

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"

	"github.com/underhax/mihomo-warp-proxy/internal/fsutil"
	"gopkg.in/yaml.v3"

	"github.com/underhax/mihomo-warp-proxy/internal/config"
	"github.com/underhax/mihomo-warp-proxy/internal/logging"
	"github.com/underhax/mihomo-warp-proxy/internal/wgcf"
)

const maxConfigSize = 1024 * 1024

const (
	yamlTagBool = "!!bool"
	yamlTagInt  = "!!int"
	yamlTagMap  = "!!map"
	yamlTagSeq  = "!!seq"
	yamlTagStr  = "!!str"
)

// EnsureConfig creates config.yaml from a minimal template when it does not
// exist, then patches it with current environment values.
// When the file already exists only owned fields are updated.
func EnsureConfig(cfg *config.Config, profile *wgcf.Profile, reserved [3]byte, log *logging.Logger) error {
	if _, err := os.Stat(cfg.Paths.MihomoConfigFile); err != nil {
		if os.IsNotExist(err) {
			log.Debug("mihomo: config not found, creating from template")
			if errTmpl := createTemplate(cfg, profile, reserved); errTmpl != nil {
				return fmt.Errorf("mihomo: create template: %w", errTmpl)
			}
			log.Debug("mihomo: config created from template")
			return nil
		}
		return fmt.Errorf("mihomo: stat config: %w", err)
	}

	log.Debug("mihomo: patching existing config")
	if err := patchConfig(cfg, profile, reserved, log); err != nil {
		return err
	}
	log.Debug("mihomo: config patched successfully")
	return nil
}

func createTemplate(cfg *config.Config, profile *wgcf.Profile, reserved [3]byte) error {
	doc := make(map[string]any)
	applyOwnedFieldsMap(doc, cfg)

	if cfg.Geo.Enabled {
		applyGeoFieldsMap(doc, cfg)
	}

	if cfg.Warp.Enabled && profile != nil {
		doc["proxies"] = []any{buildWarpProxy(cfg, profile, reserved)}
		doc["rules"] = []any{minimalTemplateWarpRule()}
	} else {
		doc["rules"] = []any{minimalTemplateDirectRule()}
	}

	return writeConfigMap(cfg.Paths.MihomoConfigFile, doc)
}

func patchConfig(cfg *config.Config, profile *wgcf.Profile, reserved [3]byte, log *logging.Logger) (retErr error) {
	f, err := os.Open(cfg.Paths.MihomoConfigFile)
	if err != nil {
		return fmt.Errorf("open config: %w", err)
	}
	defer func() {
		if closeErr := fileClose(f); closeErr != nil && retErr == nil {
			retErr = fmt.Errorf("close config: %w", closeErr)
		}
	}()

	raw, err := fileReadAll(io.LimitReader(f, maxConfigSize+1))
	if err != nil {
		return fmt.Errorf("read config: %w", err)
	}
	if len(raw) > maxConfigSize {
		return fmt.Errorf("config file exceeds max allowed size of %d bytes", maxConfigSize)
	}

	var root yaml.Node
	if err := yaml.Unmarshal(raw, &root); err != nil {
		return fmt.Errorf("parse config: %w", err)
	}

	doc := docMapping(&root)
	if doc == nil {
		return errors.New("config is not a YAML mapping")
	}

	applyOwnedFieldsNode(doc, cfg)

	if cfg.Geo.Enabled {
		applyGeoFieldsNode(doc, cfg)
	} else {
		removeGeoFieldsNode(doc)
	}

	if cfg.Warp.Enabled && profile != nil {
		patchWarpProxy(doc, cfg, profile, reserved, log)
	}

	return writeConfigNode(cfg.Paths.MihomoConfigFile, &root)
}

func applyOwnedFieldsNode(doc *yaml.Node, cfg *config.Config) {
	setNodeScalar(doc, "mixed-port", yamlTagInt, strconv.FormatUint(uint64(cfg.ProxyPort), 10))
	setNodeScalar(doc, "log-level", yamlTagStr, cfg.ProxyLogLevel)
	setNodeScalar(doc, "ipv6", yamlTagBool, boolStr(cfg.UseIP6))
	setNodeScalar(doc, "allow-lan", yamlTagBool, "true")
	setNodeScalar(doc, "bind-address", yamlTagStr, "*")

	authSeq := &yaml.Node{Kind: yaml.SequenceNode, Tag: yamlTagSeq}
	if cfg.ProxyUser != "" && cfg.ProxyPass != "" {
		authSeq.Content = append(authSeq.Content,
			&yaml.Node{Kind: yaml.ScalarNode, Tag: yamlTagStr, Value: cfg.ProxyUser + ":" + cfg.ProxyPass},
		)
	}
	setNodeValue(doc, "authentication", authSeq)
}

func applyGeoFieldsNode(doc *yaml.Node, cfg *config.Config) {
	setNodeScalar(doc, "geodata-mode", yamlTagBool, "true")
	setNodeScalar(doc, "geodata-loader", yamlTagStr, "memconservative")
	setNodeScalar(doc, "geo-auto-update", yamlTagBool, boolStr(cfg.Geo.AutoUpdate))
	setNodeScalar(doc, "geo-update-interval", yamlTagInt, "24")

	geoMap := &yaml.Node{Kind: yaml.MappingNode, Tag: yamlTagMap}
	for _, kv := range [][2]string{
		{"geoip", cfg.Geo.URLs.GeoIP},
		{"geosite", cfg.Geo.URLs.GeoSite},
		{"mmdb", cfg.Geo.URLs.MMDB},
		{"asn", cfg.Geo.URLs.ASN},
	} {
		geoMap.Content = append(geoMap.Content,
			&yaml.Node{Kind: yaml.ScalarNode, Tag: yamlTagStr, Value: kv[0]},
			&yaml.Node{Kind: yaml.ScalarNode, Tag: yamlTagStr, Value: kv[1]},
		)
	}
	setNodeValue(doc, "geox-url", geoMap)
}

func removeGeoFieldsNode(doc *yaml.Node) {
	for _, k := range []string{
		"geodata-mode", "geodata-loader", "geo-auto-update",
		"geo-update-interval", "geox-url",
	} {
		deleteNodeKey(doc, k)
	}
}

func patchWarpProxy(doc *yaml.Node, cfg *config.Config, profile *wgcf.Profile, reserved [3]byte, log *logging.Logger) {
	warpNode := buildWarpProxy(cfg, profile, reserved)

	proxiesNode := getMappingValue(doc, "proxies")
	if proxiesNode == nil || proxiesNode.Kind != yaml.SequenceNode {
		proxiesNode = &yaml.Node{Kind: yaml.SequenceNode, Tag: yamlTagSeq}
		setNodeValue(doc, "proxies", proxiesNode)
	}

	idx := findProxyByNameNode(proxiesNode, "warp")
	if idx < 0 {
		log.Debug("mihomo: warp proxy not found — appending to proxies list")

		if len(proxiesNode.Content) == 0 && isMinimalTemplateNode(doc) {
			rulesNode := getMappingValue(doc, "rules")
			if rulesNode != nil && len(rulesNode.Content) == 1 {
				rulesNode.Content[0].Value = minimalTemplateWarpRule()
				log.Debug("mihomo: replaced MATCH,DIRECT with MATCH,warp in minimal template config")
			}
		}

		proxiesNode.Content = append(proxiesNode.Content, warpNode)
		return
	}

	proxiesNode.Content[idx] = warpNode
}

func minimalTemplateDirectRule() string {
	return "MATCH,DIRECT"
}

func minimalTemplateWarpRule() string {
	return "MATCH,warp"
}

func isMinimalTemplateNode(doc *yaml.Node) bool {
	proxiesNode := getMappingValue(doc, "proxies")
	if proxiesNode != nil && len(proxiesNode.Content) != 0 {
		return false
	}
	rulesNode := getMappingValue(doc, "rules")
	if rulesNode == nil || rulesNode.Kind != yaml.SequenceNode || len(rulesNode.Content) != 1 {
		return false
	}
	return rulesNode.Content[0].Value == minimalTemplateDirectRule()
}

func buildWarpProxy(cfg *config.Config, profile *wgcf.Profile, reserved [3]byte) *yaml.Node {
	server, port := splitEndpoint(cfg.Warp.Endpoint)
	n := &yaml.Node{Kind: yaml.MappingNode, Tag: yamlTagMap}

	addStr := func(k, v string) {
		n.Content = append(n.Content, strNode(k), strNode(v))
	}
	addInt := func(k string, v int) {
		n.Content = append(n.Content, strNode(k), intNode(v))
	}
	addBool := func(k string, v bool) {
		n.Content = append(n.Content, strNode(k), boolNode(v))
	}

	addStr("name", "warp")
	addStr("type", "wireguard")
	addStr("client-fingerprint", "chrome")
	addStr("server", server)
	addInt("port", port)
	addStr("ip", profile.IPv4)
	addStr("ipv6", profile.IPv6)
	addStr("public-key", profile.PublicKey)
	addStr("private-key", profile.PrivateKey)

	if reserved != [3]byte{0, 0, 0} {
		seq := &yaml.Node{Kind: yaml.SequenceNode, Tag: yamlTagSeq}
		for _, b := range reserved {
			seq.Content = append(seq.Content, intNode(int(b)))
		}
		n.Content = append(n.Content, strNode("reserved"), seq)
	}

	addBool("udp", true)
	addInt("mtu", 1280)
	addBool("remote-dns-resolve", true)

	dnsSeq := &yaml.Node{Kind: yaml.SequenceNode, Tag: yamlTagSeq}
	for _, d := range cfg.Warp.DNS {
		dnsSeq.Content = append(dnsSeq.Content, strNode(d))
	}
	n.Content = append(n.Content, strNode("dns"), dnsSeq)
	addInt("refresh-server-ip-interval", 60)

	if cfg.Warp.Amnezia.Enabled {
		n.Content = append(n.Content, strNode("amnezia-wg-option"), buildAmneziaNode(cfg))
	}

	return n
}

func buildAmneziaNode(cfg *config.Config) *yaml.Node {
	a := cfg.Warp.Amnezia
	n := &yaml.Node{Kind: yaml.MappingNode, Tag: yamlTagMap}

	addInt := func(k string, v int) {
		n.Content = append(n.Content, strNode(k), intNode(v))
	}
	addStr := func(k, v string) {
		n.Content = append(n.Content, strNode(k), strNode(v))
	}

	addInt("jc", a.JC)
	addInt("jmin", a.JMin)
	addInt("jmax", a.JMax)
	addInt("s1", 0)
	addInt("s2", 0)
	addInt("h1", 1)
	addInt("h2", 2)
	addInt("h3", 3)
	addInt("h4", 4)
	for i, val := range a.I {
		if val != "" {
			addStr(fmt.Sprintf("i%d", i+1), val)
		}
	}
	return n
}

func docMapping(root *yaml.Node) *yaml.Node {
	if root.Kind == yaml.DocumentNode && len(root.Content) > 0 {
		if root.Content[0].Kind == yaml.MappingNode {
			return root.Content[0]
		}
	}
	if root.Kind == yaml.MappingNode {
		return root
	}
	return nil
}

func getMappingValue(doc *yaml.Node, key string) *yaml.Node {
	for i := 0; i+1 < len(doc.Content); i += 2 {
		if doc.Content[i].Value != key {
			continue
		}
		return doc.Content[i+1]
	}
	return nil
}

func setNodeScalar(doc *yaml.Node, key, tag, value string) {
	for i := 0; i+1 < len(doc.Content); i += 2 {
		if doc.Content[i].Value != key {
			continue
		}
		doc.Content[i+1].Kind = yaml.ScalarNode
		doc.Content[i+1].Tag = tag
		doc.Content[i+1].Value = value
		doc.Content[i+1].Content = nil
		return
	}
	doc.Content = append(doc.Content,
		&yaml.Node{Kind: yaml.ScalarNode, Tag: yamlTagStr, Value: key},
		&yaml.Node{Kind: yaml.ScalarNode, Tag: tag, Value: value},
	)
}

func setNodeValue(doc *yaml.Node, key string, val *yaml.Node) {
	for i := 0; i+1 < len(doc.Content); i += 2 {
		if doc.Content[i].Value != key {
			continue
		}
		doc.Content[i+1] = val
		return
	}
	doc.Content = append(doc.Content,
		&yaml.Node{Kind: yaml.ScalarNode, Tag: yamlTagStr, Value: key},
		val,
	)
}

func deleteNodeKey(doc *yaml.Node, key string) {
	for i := 0; i+1 < len(doc.Content); i += 2 {
		if doc.Content[i].Value != key {
			continue
		}
		doc.Content = append(doc.Content[:i], doc.Content[i+2:]...)
		return
	}
}

func findProxyByNameNode(seq *yaml.Node, name string) int {
	for i, item := range seq.Content {
		if item.Kind == yaml.MappingNode && yamlNodeName(item) == name {
			return i
		}
	}
	return -1
}

func yamlNodeName(n *yaml.Node) string {
	if n == nil || n.Kind != yaml.MappingNode {
		return ""
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value == "name" {
			return n.Content[i+1].Value
		}
	}
	return ""
}

func strNode(v string) *yaml.Node {
	return &yaml.Node{Kind: yaml.ScalarNode, Tag: yamlTagStr, Value: v}
}

func intNode(v int) *yaml.Node {
	return &yaml.Node{Kind: yaml.ScalarNode, Tag: yamlTagInt, Value: strconv.Itoa(v)}
}

func boolNode(v bool) *yaml.Node {
	return &yaml.Node{Kind: yaml.ScalarNode, Tag: yamlTagBool, Value: boolStr(v)}
}

func boolStr(v bool) string {
	if v {
		return "true"
	}
	return "false"
}

func applyOwnedFieldsMap(doc map[string]any, cfg *config.Config) {
	doc["mixed-port"] = int(cfg.ProxyPort)
	doc["log-level"] = cfg.ProxyLogLevel
	doc["ipv6"] = cfg.UseIP6
	doc["allow-lan"] = true
	doc["bind-address"] = "*"

	if cfg.ProxyUser != "" && cfg.ProxyPass != "" {
		doc["authentication"] = []any{cfg.ProxyUser + ":" + cfg.ProxyPass}
	} else {
		doc["authentication"] = []any{}
	}
}

func applyGeoFieldsMap(doc map[string]any, cfg *config.Config) {
	doc["geodata-mode"] = true
	doc["geodata-loader"] = "memconservative"
	doc["geo-auto-update"] = cfg.Geo.AutoUpdate
	doc["geo-update-interval"] = 24
	doc["geox-url"] = map[string]any{
		"geoip":   cfg.Geo.URLs.GeoIP,
		"geosite": cfg.Geo.URLs.GeoSite,
		"mmdb":    cfg.Geo.URLs.MMDB,
		"asn":     cfg.Geo.URLs.ASN,
	}
}

func splitEndpoint(endpoint string) (host string, port int) {
	host, portStr, err := net.SplitHostPort(endpoint)
	if err != nil {
		return endpoint, 0
	}
	port, err = strconv.Atoi(portStr)
	if err != nil {
		return host, 0
	}
	return host, port
}

func writeConfigNode(path string, root *yaml.Node) error {
	data, err := yamlMarshal(root)
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}
	if err := fsutil.AtomicWrite(path, data, 0o600); err != nil {
		return fmt.Errorf("atomic write: %w", err)
	}
	return nil
}

func writeConfigMap(path string, doc map[string]any) error {
	data, err := yamlMarshal(doc)
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}
	if err := fsutil.AtomicWrite(path, data, 0o600); err != nil {
		return fmt.Errorf("atomic write: %w", err)
	}
	return nil
}

func defaultFileClose(f *os.File) error {
	if err := f.Close(); err != nil {
		return fmt.Errorf("close file: %w", err)
	}
	return nil
}

func defaultFileReadAll(r io.Reader) ([]byte, error) {
	buf, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("read file: %w", err)
	}
	return buf, nil
}

func defaultYAMLMarshal(in any) ([]byte, error) {
	b, err := yaml.Marshal(in)
	if err != nil {
		return nil, fmt.Errorf("yaml marshal: %w", err)
	}
	return b, nil
}

var (
	fileClose   = defaultFileClose
	fileReadAll = defaultFileReadAll
	yamlMarshal = defaultYAMLMarshal
)
