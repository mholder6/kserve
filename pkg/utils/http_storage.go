/*
Copyright 2026 The KServe Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package utils

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const ErrBlockedHTTPStorageURI = "http(s) storageUri %q targets a blocked host or IP"

var lookupIPFn = net.LookupIP

// CheckHTTPStorageURI rejects http(s) URIs whose host is a blocked IP literal
// or a well-known internal/metadata hostname. Non-http(s) URIs are ignored.
// DNS is deliberately not resolved so admission remains offline-safe.
func CheckHTTPStorageURI(rawURI string) error {
	return checkHTTPStorageURI(rawURI, false)
}

// CheckHTTPStorageURIResolved also resolves hostnames. Fetchers should use this
// check and SafeHTTPClient to cover redirects and the final dial.
func CheckHTTPStorageURIResolved(rawURI string) error {
	return checkHTTPStorageURI(rawURI, true)
}

func checkHTTPStorageURI(rawURI string, resolve bool) error {
	parsed, err := url.Parse(rawURI)
	if err != nil {
		return fmt.Errorf("invalid storageUri: %w", err)
	}
	scheme := strings.ToLower(parsed.Scheme)
	if scheme != "http" && scheme != "https" {
		return nil
	}
	host := parsed.Hostname()
	if host == "" {
		return fmt.Errorf(ErrBlockedHTTPStorageURI, rawURI)
	}
	if err := checkHTTPStorageHost(host, resolve); err != nil {
		return fmt.Errorf(ErrBlockedHTTPStorageURI, rawURI)
	}
	return nil
}

func checkHTTPStorageHost(host string, resolve bool) error {
	if isBlockedHostname(host) || isBlockedIPLiteral(host) || isObfuscatedIPv4(host) {
		return fmt.Errorf("blocked host %q", host)
	}
	if !resolve {
		return nil
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return nil
	}
	ips, err := lookupIPFn(host)
	if err != nil {
		return fmt.Errorf("resolve host %q: %w", host, err)
	}
	if len(ips) == 0 {
		return fmt.Errorf("host %q resolved to no addresses", host)
	}
	for _, ip := range ips {
		addr, ok := netip.AddrFromSlice(ip)
		if ok && isBlockedAddr(addr) {
			return fmt.Errorf("blocked resolved IP %s for host %q", addr, host)
		}
	}
	return nil
}

func isBlockedHostname(host string) bool {
	h := strings.ToLower(strings.TrimSuffix(host, "."))
	switch h {
	case "localhost", "metadata", "metadata.google.internal",
		"kubernetes", "kubernetes.default", "kubernetes.default.svc",
		"kubernetes.default.svc.cluster.local",
		"host.docker.internal", "host.containers.internal":
		return true
	}
	return strings.HasSuffix(h, ".localhost") ||
		strings.HasSuffix(h, ".svc") ||
		strings.HasSuffix(h, ".cluster.local") ||
		strings.HasSuffix(h, ".internal")
}

func isBlockedIPLiteral(host string) bool {
	addr, err := netip.ParseAddr(host)
	return err == nil && isBlockedAddr(addr)
}

func isBlockedAddr(addr netip.Addr) bool {
	addr = addr.Unmap()
	return addr.IsLoopback() || addr.IsPrivate() ||
		addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() ||
		addr.IsMulticast() || addr.IsUnspecified()
}

// Catch dword and octal spellings that URL parsers may pass to HTTP stacks.
func isObfuscatedIPv4(host string) bool {
	if _, err := strconv.ParseUint(host, 10, 32); err == nil {
		return true
	}
	parts := strings.Split(host, ".")
	if len(parts) != 4 {
		return false
	}
	for _, part := range parts {
		if len(part) > 1 && part[0] == '0' {
			return true
		}
		if _, err := strconv.ParseUint(part, 10, 8); err != nil {
			return false
		}
	}
	return false
}

// SafeHTTPClient returns a shallow copy which checks redirect targets and
// rejects dials to internal addresses. Unknown RoundTrippers retain redirect
// protection but cannot be wrapped at the dial layer.
func SafeHTTPClient(client *http.Client) *http.Client {
	if client == nil {
		client = &http.Client{}
	}
	out := *client
	originalRedirect := out.CheckRedirect
	out.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if err := CheckHTTPStorageURIResolved(req.URL.String()); err != nil {
			return err
		}
		if originalRedirect != nil {
			return originalRedirect(req, via)
		}
		if len(via) >= 10 {
			return errors.New("stopped after 10 redirects")
		}
		return nil
	}
	out.Transport = wrapSafeTransport(out.Transport)
	return &out
}

func wrapSafeTransport(roundTripper http.RoundTripper) http.RoundTripper {
	var transport *http.Transport
	switch typed := roundTripper.(type) {
	case *http.Transport:
		transport = typed.Clone()
	case nil:
		transport = http.DefaultTransport.(*http.Transport).Clone()
	default:
		return roundTripper
	}
	baseDial := transport.DialContext
	if baseDial == nil {
		dialer := &net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}
		baseDial = dialer.DialContext
	}
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			host = address
		}
		if err := checkHTTPStorageHost(host, true); err != nil {
			return nil, fmt.Errorf(ErrBlockedHTTPStorageURI, address)
		}
		return baseDial(ctx, network, address)
	}
	return transport
}
