package http

import (
	"context"
	"net/http"
	"strconv"
	"strings"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
)

// ApplyTrustedXForwardedFor returns remoteAddr overridden by the first IP in
// X-Forwarded-For when a configured trusted header is present, or when no
// trusted headers are configured (trusting the proxy chain by default).
func ApplyTrustedXForwardedFor(header http.Header, trusted []string, remoteAddr net.Addr) net.Addr {
	value := header.Get("X-Forwarded-For")
	if value == "" {
		return remoteAddr
	}
	if idx := strings.IndexByte(value, ','); idx >= 0 {
		value = value[:idx]
	}
	addr := net.ParseAddress(value)
	if !addr.Family().IsIP() {
		return remoteAddr
	}
	if len(trusted) > 0 {
		trustedFound := false
		for _, t := range trusted {
			if len(header.Values(t)) > 0 {
				trustedFound = true
				break
			}
		}
		if !trustedFound {
			errors.LogError(context.Background(), `ignored potentially forged "X-Forwarded-For" from `, remoteAddr, `: `, value)
			return remoteAddr
		}
	}
	return &net.TCPAddr{
		IP:   addr.IP(),
		Port: 0,
	}
}

// RemoveHopByHopHeaders removes hop by hop headers in http header list.
func RemoveHopByHopHeaders(header http.Header) {
	// Strip hop-by-hop header based on RFC:
	// http://www.w3.org/Protocols/rfc2616/rfc2616-sec13.html#sec13.5.1
	// https://www.mnot.net/blog/2011/07/11/what_proxies_must_do

	header.Del("Proxy-Connection")
	header.Del("Proxy-Authenticate")
	header.Del("Proxy-Authorization")
	header.Del("TE")
	header.Del("Trailers")
	header.Del("Transfer-Encoding")
	header.Del("Upgrade")

	connections := header.Get("Connection")
	header.Del("Connection")
	if connections == "" {
		return
	}
	for _, h := range strings.Split(connections, ",") {
		header.Del(strings.TrimSpace(h))
	}
}

// ParseHost splits host and port from a raw string. Default port is used when raw string doesn't contain port.
func ParseHost(rawHost string, defaultPort net.Port) (net.Destination, error) {
	port := defaultPort
	host, rawPort, err := net.SplitHostPort(rawHost)
	if err != nil {
		if addrError, ok := err.(*net.AddrError); ok && strings.Contains(addrError.Err, "missing port") {
			host = rawHost
		} else {
			return net.Destination{}, err
		}
	} else if len(rawPort) > 0 {
		intPort, err := strconv.Atoi(rawPort)
		if err != nil {
			return net.Destination{}, err
		}
		port = net.Port(intPort)
	}

	return net.TCPDestination(net.ParseAddress(host), port), nil
}
