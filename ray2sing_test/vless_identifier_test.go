package ray2sing_test

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/hiddify/ray2sing/ray2sing"
)

// Same deterministic synthetic fixture and fingerprint as the offline reproduction.
func problematicVlessIdentifier(t *testing.T) string {
	t.Helper()
	for i := 0; i < 100000; i++ {
		h := sha256.Sum256([]byte(fmt.Sprintf("synthetic-offline-%d", i)))
		h[6] = (h[6] & 15) | 64
		h[8] = (h[8] & 63) | 128
		s := hex.EncodeToString(h[:16])
		id := s[:8] + "-" + s[8:12] + "-" + s[12:16] + "-" + s[16:20] + "-" + s[20:]
		decoded, err := base64.URLEncoding.DecodeString(id)
		if err == nil && strings.Contains(string(decoded), ":") {
			fingerprint := sha256.Sum256([]byte(id))
			if hex.EncodeToString(fingerprint[:]) != "f33569bdc9f08b38a603845bdf47c2b25de12dc96c6a8063616d722282530446" {
				t.Fatal("reproduction fixture fingerprint changed")
			}
			return id
		}
	}
	t.Fatal("synthetic fixture unavailable")
	return ""
}

func convertedSingleVless(t *testing.T, input string) string {
	t.Helper()
	output, err := ray2sing.Ray2Singbox(input, false)
	if err != nil {
		t.Fatal("synthetic converter returned an error")
	}
	var config struct {
		Outbounds []struct {
			Type string `json:"type"`
			UUID string `json:"uuid"`
		} `json:"outbounds"`
	}
	if json.Unmarshal([]byte(output), &config) != nil {
		t.Fatal("invalid converted JSON")
	}
	count := 0
	var identifier string
	for _, outbound := range config.Outbounds {
		if outbound.Type == "vless" {
			count++
			identifier = outbound.UUID
		}
	}
	if count != 1 {
		t.Fatal("expected exactly one VLESS outbound")
	}
	return identifier
}

func TestVlessAuthenticationIdentifier(t *testing.T) {
	problematic := problematicVlessIdentifier(t)
	control := "00000000-0000-4000-8000-000000000000"
	for _, tc := range []struct{ name, identifier, userinfo string }{
		{"problematic", problematic, problematic},
		{"control", control, control},
		{"percent_encoded", problematic, strings.ReplaceAll(problematic, "-", "%2D")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			uri := "vless://" + tc.userinfo + "@127.0.0.1:24443?type=tcp&security=none#synthetic"
			for _, encoded := range []bool{false, true} {
				input := uri
				if encoded {
					input = base64.StdEncoding.EncodeToString([]byte(uri))
				}
				if convertedSingleVless(t, input) != tc.identifier {
					t.Fatal("converter changed VLESS authentication identifier")
				}
			}
		})
	}
}

func TestVlessUserinfoParsingContract(t *testing.T) {
	id := problematicVlessIdentifier(t)
	for _, scheme := range []string{"vless", "svless", "xvless"} {
		t.Run(scheme, func(t *testing.T) {
			parsed, err := ray2sing.ParseUrl(scheme+"://"+strings.ReplaceAll(id, "-", "%2D")+"@127.0.0.1:24443?type=tcp", 443)
			if err != nil || parsed.Username != id || parsed.Password != "" {
				t.Fatal("VLESS userinfo must retain percent-decoded authentication identifier")
			}
		})
	}
	for _, suffix := range []string{"%ZZ@127.0.0.1:24443?type=tcp", "synthetic@127.0.0.1:invalid?type=tcp"} {
		t.Run("malformed_"+fmt.Sprint(len(suffix)), func(t *testing.T) {
			uri := "vless://" + suffix
			if _, err := ray2sing.ParseUrl(uri, 443); err == nil {
				t.Fatal("expected URL parse error")
			}
			if _, err := ray2sing.VlessSingbox(uri); err == nil {
				t.Fatal("expected converter parse error")
			}
			if _, err := ray2sing.Ray2Singbox(uri, false); err == nil {
				t.Fatal("expected top-level conversion error")
			}
		})
	}
	// Preserve the existing parser contract: it does not validate missing credentials.
	parsed, err := ray2sing.ParseUrl("vless://127.0.0.1:24443?type=tcp", 443)
	if err != nil || parsed.Username != "" {
		t.Fatal("missing-userinfo parser contract changed")
	}
}

func TestVlessUserinfoPercentDecodedOnce(t *testing.T) {
	for _, tc := range []struct{ userinfo, identifier string }{
		{"synthetic%3Aidentifier", "synthetic:identifier"},
		{"synthetic%252Didentifier", "synthetic%2Didentifier"},
	} {
		uri := "vless://" + tc.userinfo + "@127.0.0.1:24443?type=tcp"
		if convertedSingleVless(t, uri) != tc.identifier {
			t.Fatal("converter changed URI percent-decoding semantics")
		}
	}
}

func TestOtherProtocolEncodedUserinfoUnchanged(t *testing.T) {
	encoded := base64.StdEncoding.EncodeToString([]byte("synthetic-user:synthetic-password"))
	for _, scheme := range []string{"ss", "socks", "http", "https", "phttp", "phttps", "ssh", "trojan", "xtrojan", "strojan", "tuic", "hy2", "hysteria2", "hysteria", "wg", "wireguard", "direct", "xdirect", "warp"} {
		t.Run(scheme, func(t *testing.T) {
			parsed, err := ray2sing.ParseUrl(scheme+"://"+encoded+"@127.0.0.1:24443", 443)
			if err != nil || parsed.Username != "synthetic-user" || parsed.Password != "synthetic-password" {
				t.Fatal("non-VLESS Base64 pair behavior changed")
			}
		})
	}
}

func TestSyntheticShadowsocksEncodedUserinfo(t *testing.T) {
	encoded := base64.URLEncoding.EncodeToString([]byte("chacha20-ietf-poly1305:synthetic-password:with-colon"))
	for _, userinfo := range []string{encoded, strings.ReplaceAll(encoded, "=", "%3D")} {
		out, err := ray2sing.ShadowsocksSingbox("ss://" + userinfo + "@127.0.0.1:24443")
		if err != nil || out.ShadowsocksOptions.Method != "chacha20-ietf-poly1305" || out.ShadowsocksOptions.Password != "synthetic-password:with-colon" {
			t.Fatal("Shadowsocks encoded credentials changed")
		}
	}
}
