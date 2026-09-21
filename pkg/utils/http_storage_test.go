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
	"net"
	"net/http"
	"testing"
)

func TestCheckHTTPStorageURI(t *testing.T) {
	tests := []struct {
		uri     string
		blocked bool
	}{
		{uri: "s3://bucket/model"},
		{uri: "https://example.com/model.joblib"},
		{uri: "https://kfserving.blob.core.windows.net/triton/model"},
		{uri: "http://127.0.0.1/model", blocked: true},
		{uri: "http://[::1]/model", blocked: true},
		{uri: "http://localhost/model", blocked: true},
		{uri: "http://169.254.169.254/latest/meta-data", blocked: true},
		{uri: "http://10.0.0.1/model", blocked: true},
		{uri: "https://kubernetes.default.svc/api", blocked: true},
		{uri: "http://2130706433/model", blocked: true},
		{uri: "http://0177.0.0.1/model", blocked: true},
		{uri: "http://[fd00::1]/model", blocked: true},
	}
	for _, test := range tests {
		t.Run(test.uri, func(t *testing.T) {
			err := CheckHTTPStorageURI(test.uri)
			if (err != nil) != test.blocked {
				t.Fatalf("CheckHTTPStorageURI() error = %v, blocked = %v", err, test.blocked)
			}
		})
	}
}

func TestCheckHTTPStorageURIResolvedPrivateDNS(t *testing.T) {
	original := lookupIPFn
	t.Cleanup(func() { lookupIPFn = original })
	lookupIPFn = func(string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("169.254.169.254")}, nil
	}
	if err := CheckHTTPStorageURIResolved("http://evil.example/model"); err == nil {
		t.Fatal("expected resolved metadata address to be blocked")
	}
}

func TestSafeHTTPClientRejectsLoopbackRedirectAndDial(t *testing.T) {
	client := SafeHTTPClient(nil)
	request, err := http.NewRequest(http.MethodGet, "http://127.0.0.1/model", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.CheckRedirect(request, nil); err == nil {
		t.Fatal("expected redirect to loopback to be blocked")
	}
	transport := client.Transport.(*http.Transport)
	if _, err := transport.DialContext(t.Context(), "tcp", "127.0.0.1:1"); err == nil {
		t.Fatal("expected loopback dial to be blocked")
	}
}
