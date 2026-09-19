// Package contract defines operator-facing names that must remain consistent
// across packages. Centralising these strings avoids drift between runtime
// configuration loading, validation, logging, and tests.
package contract

// Environment variable names configuring container initialization and services.
const (
	EnvTZ                 = "TZ"
	EnvScriptLogLevel     = "SCRIPT_LOG_LEVEL"
	EnvProxyLogLevel      = "PROXY_LOG_LEVEL"
	EnvProxyUID           = "PROXY_UID"
	EnvProxyGID           = "PROXY_GID"
	EnvProxyPort          = "PROXY_PORT"
	EnvProxyUser          = "PROXY_USER"
	EnvProxyPass          = "PROXY_" + "PASS"
	EnvMultiUserMode      = "MULTI_USER_MODE"
	EnvUseIP6             = "USE_IP6"
	EnvGeo                = "GEO"
	EnvGeoRedownload      = "GEO_REDOWNLOAD"
	EnvGeoAutoUpdate      = "GEO_AUTO_UPDATE"
	EnvGeoURLGeoIP        = "GEO_URL_GEOIP"
	EnvGeoURLGeoSite      = "GEO_URL_GEOSITE"
	EnvGeoURLMMDB         = "GEO_URL_MMDB"
	EnvGeoURLASN          = "GEO_URL_ASN"
	EnvGeoAuthUser        = "GEO_AUTH_USER"
	EnvGeoAuthSecret      = "GEO_AUTH_" + "PASS"
	EnvUseWarpConfig      = "USE_WARP_CONFIG"
	EnvWarpRegenerate     = "WARP_REGENERATE"
	EnvWarpPlusKey        = "WARP_PLUS_" + "KEY"
	EnvWarpEndpoint       = "WARP_ENDPOINT"
	EnvWarpDNS            = "WARP_DNS"
	EnvWarpAmnezia        = "WARP_AMNEZIA"
	EnvWarpAmneziaJC      = "WARP_AMNEZIA_JC"
	EnvWarpAmneziaJMin    = "WARP_AMNEZIA_JMIN"
	EnvWarpAmneziaJMax    = "WARP_AMNEZIA_JMAX"
	EnvWarpAmneziaIPrefix = "WARP_AMNEZIA_I"
)
