# Route and API map

## Page routes
| URL | Source | Layout / role |
| --- | --- | --- |
| `/dashboard` | `internal/dashboard/handler.go` | Permanent redirect to `/dashboard/` |
| `/dashboard/` | `internal/dashboard/assets/index.html` | Complete operator dashboard shell |
| `/dashboard/index.html` | Same | Same page |
| `/dashboard/styles.css`, `/dashboard/live.js`, `/dashboard/app.js` | `internal/dashboard/assets/` | Embedded assets, hash query versioning |

Navigation is in-page anchors: `#overview`, `#simulation`, `#recent`, `#pipeline`, `#sources`, `#activity`, `#connection`. `#scope` and `#main-content` are additional section/accessibility targets. There is no client-side router, no separate settings/users/tasks pages, and no frontend root `/` route in these assets. Do not invent unimplemented navigation destinations.

## Existing API contracts
- Readiness: `GET /health/ready`, no bearer header, status determines readiness.
- Dashboard summary: `GET /api/v1/dashboard/summary?tenant_id=<encoded tenant>`.
- Recent event fallback: `GET /api/v1/events?tenant_id=<encoded tenant>&limit=50`.
- Trace metadata: `GET /api/v1/events/<encoded revision_id>` and `GET /api/v1/receipts/<encoded receipt_id>`; allowlisted same-origin federated event/receipt URLs may be supplied by metadata.
- Simulation ingestion: `POST /api/v1/ingest`, `Content-Type: application/octet-stream`, payload is synthetic source log. Ingestion tenant is configured by server, not the dashboard tenant selector. Accepted events persist; stopping or clearing console does not remove them.
- Data requests send `Authorization: Bearer <token>`, `Accept: application/json`, `credentials: same-origin`, `cache: no-store`.
- Tenant/token persist in current tab sessionStorage under `ulpf.dashboard.tenant` and `ulpf.dashboard.token`; never bake credentials into UI/artifacts.
- Refresh every 2 seconds while visible, connected and unpaused, with 8-second abort timeout. Summary and fallback event request failures support partial availability.
- Environment/instance/source/format/status/search filters scope actual returned data. No fake counters, synthetic historical chart samples or invented tenant content.
- Trace inspector shows receipt, raw-evidence metadata, revision and canonical envelope. It does not fetch/display raw evidence.
- Simulation scenarios `all`, `security`, `operations`, `endpoint`; speeds `1`, `2`, `4`; three-minute limit; last 80 input previews; stop on page hide, hidden tab, refresh pause or unavailable telemetry.

## Complete dashboard route handler
Source: `internal/dashboard/handler.go`. Only four asset filenames are served; new asset types require an intentional handler change. CSP restricts scripts/styles/fonts/connects to same origin; do not add CDN dependencies, external fonts, inline scripts or inline style blocks.

```go
// Package dashboard serves the embedded ULPF operator dashboard.
package dashboard

import (
	"bytes"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"io/fs"
	"mime"
	"net/http"
	"path"
	"strings"
)

//go:embed assets/*
var embedded embed.FS

const contentSecurityPolicy = "default-src 'self'; connect-src 'self'; img-src 'self' data:; script-src 'self'; style-src 'self'; font-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"

// Handler returns a self-contained HTTP handler rooted at /dashboard/.
// Dashboard assets are compiled into the binary and never require a CDN or
// network access beyond the ULPF API served by the same origin.
func Handler() http.Handler {
	assets, err := fs.Sub(embedded, "assets")
	if err != nil {
		panic(err)
	}
	assetBodies := make(map[string][]byte, 4)
	for _, name := range []string{"index.html", "styles.css", "live.js", "app.js"} {
		body, readErr := fs.ReadFile(assets, name)
		if readErr != nil {
			panic(readErr)
		}
		assetBodies[name] = body
	}
	for _, name := range []string{"styles.css", "live.js", "app.js"} {
		digest := sha256.Sum256(assetBodies[name])
		plainURL := []byte("/dashboard/" + name)
		versionedURL := []byte("/dashboard/" + name + "?v=" + hex.EncodeToString(digest[:6]))
		assetBodies["index.html"] = bytes.ReplaceAll(assetBodies["index.html"], plainURL, versionedURL)
	}
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		setSecurityHeaders(writer.Header())
		if request.Method != http.MethodGet && request.Method != http.MethodHead {
			writer.Header().Set("Allow", "GET, HEAD")
			http.Error(writer, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if request.URL.Path == "/dashboard" {
			http.Redirect(writer, request, "/dashboard/", http.StatusPermanentRedirect)
			return
		}
		if !strings.HasPrefix(request.URL.Path, "/dashboard/") {
			http.NotFound(writer, request)
			return
		}
		name := strings.TrimPrefix(request.URL.Path, "/dashboard/")
		if name == "" {
			name = "index.html"
		}
		if name != "index.html" && name != "styles.css" && name != "live.js" && name != "app.js" {
			http.NotFound(writer, request)
			return
		}
		body, found := assetBodies[name]
		if !found {
			http.NotFound(writer, request)
			return
		}
		digest := sha256.Sum256(body)
		etag := `"sha256-` + hex.EncodeToString(digest[:]) + `"`
		writer.Header().Set("ETag", etag)
		if request.Header.Get("If-None-Match") == etag {
			writer.WriteHeader(http.StatusNotModified)
			return
		}
		contentType := mime.TypeByExtension(path.Ext(name))
		if contentType == "" {
			contentType = "application/octet-stream"
		}
		writer.Header().Set("Content-Type", contentType)
		if name == "index.html" {
			writer.Header().Set("Cache-Control", "no-store")
		} else {
			writer.Header().Set("Cache-Control", "public, max-age=0, must-revalidate")
		}
		writer.Header().Set("Content-Length", stringLength(len(body)))
		writer.WriteHeader(http.StatusOK)
		if request.Method == http.MethodGet {
			_, _ = writer.Write(body)
		}
	})
}

func setSecurityHeaders(header http.Header) {
	header.Set("Content-Security-Policy", contentSecurityPolicy)
	header.Set("Referrer-Policy", "no-referrer")
	header.Set("X-Content-Type-Options", "nosniff")
	header.Set("X-Frame-Options", "DENY")
	header.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
}

func stringLength(value int) string {
	if value == 0 {
		return "0"
	}
	var digits [20]byte
	position := len(digits)
	for value > 0 {
		position--
		digits[position] = byte('0' + value%10)
		value /= 10
	}
	return string(digits[position:])
}
```
