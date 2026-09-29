// Package dashboard serves the embedded ULPF operator dashboard.
package dashboard

import (
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
		if name != "index.html" && name != "styles.css" && name != "app.js" {
			http.NotFound(writer, request)
			return
		}
		body, readErr := fs.ReadFile(assets, name)
		if readErr != nil {
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
			writer.Header().Set("Cache-Control", "public, max-age=3600, must-revalidate")
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
