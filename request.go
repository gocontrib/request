package request

// Borrowed from drone.io

import (
	"net/http"
	"strings"
)

// ParseHeader parses non unique headers value
// from a http.Request and return a slice of the values
// queried from the header
func ParseHeader(r *http.Request, header string, token string) (val []string) {
	for _, v := range r.Header[header] {
		options := strings.Split(v, ";")
		for _, o := range options {
			keyvalue := strings.Split(o, "=")
			var key, value string
			if len(keyvalue) > 1 {
				key, value = strings.TrimSpace(keyvalue[0]), strings.TrimSpace(keyvalue[1])
			}
			key = strings.ToLower(key)
			if key == token {
				val = append(val, value)
			}
		}
	}
	return
}

// IsHTTPS is a helper function that evaluates the http.Request
// and returns True if the Request uses HTTPS. It is able to detect,
// using the X-Forwarded-Proto, if the original request was HTTPS and
// routed through a reverse proxy with SSL termination.
func IsHTTPS(r *http.Request) bool {
	return GetScheme(r) == "https"
}

// GetScheme is a helper function that evaluates the http.Request
// and returns the scheme, HTTP or HTTPS. It is able to detect,
// using the X-Forwarded-Proto, if the original request was HTTPS
// and routed through a reverse proxy with SSL termination.
func GetScheme(r *http.Request) string {
	v := ParseHeader(r, "Forwarded", "proto")
	if len(v) != 0 && v[0] == "https" {
		return "https"
	}
	switch {
	case r.Header.Get("X-Forwarded-Proto") == "https":
		return "https"
	case r.URL.Scheme == "https":
		return "https"
	case r.TLS != nil:
		return "https"
	case strings.HasPrefix(r.Proto, "HTTPS"):
		return "https"
	default:
		return "http"
	}
}

// GetHost is a helper function that evaluates the http.Request
// and returns the hostname. It is able to detect, using the
// X-Forarded-For header, the original hostname when routed
// through a reverse proxy.
func GetHost(r *http.Request) string {
	v := ParseHeader(r, "Forwarded", "host")
	if len(v) != 0 {
		return v[0]
	}
	v = ParseHeader(r, "Forwarded", "for")
	if len(v) != 0 {
		// TODO add port?
		return v[0]
	}
	switch {
	case len(r.Header.Get("X-Forwarded-Host")) != 0:
		return r.Header.Get("X-Forwarded-Host")
	case len(r.Header.Get("X-Host")) != 0:
		return r.Header.Get("X-Host")
	case len(r.Header.Get("XFF")) != 0:
		return r.Header.Get("XFF")
	case len(r.Header.Get("X-Real-IP")) != 0:
		return r.Header.Get("X-Real-IP")
	case len(r.Host) != 0:
		return r.Host
	case len(r.URL.Host) != 0:
		return r.URL.Host
	default:
		// TODO configurable default host
		return "localhost:8000"
	}
}

// GetURL is a helper function that evaluates the http.Request
// and returns the URL as a string. Only the scheme + hostname
// are included; the path is excluded.
func GetURL(r *http.Request) string {
	return GetScheme(r) + "://" + GetHost(r)
}

// GetCookie retrieves and verifies the cookie value.
func GetCookie(r *http.Request, name string) (value string) {
	cookie, err := r.Cookie(name)
	if err != nil {
		return
	}
	value = cookie.Value
	return
}

// SetCookie writes the cookie value.
func SetCookie(w http.ResponseWriter, r *http.Request, name, value string) {
	cookie := http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		Domain:   r.URL.Host,
		HttpOnly: true,
		Secure:   IsHTTPS(r),
	}

	http.SetCookie(w, &cookie)
}

// DelCookie deletes a cookie.
func DelCookie(w http.ResponseWriter, r *http.Request, name string) {
	cookie := http.Cookie{
		Name:   name,
		Value:  "deleted",
		Path:   "/",
		Domain: r.URL.Host,
		MaxAge: -1,
	}

	http.SetCookie(w, &cookie)
}
