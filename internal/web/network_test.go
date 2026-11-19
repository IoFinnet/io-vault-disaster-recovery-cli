// Copyright (C) 2021 io finnet group, inc.
// SPDX-License-Identifier: AGPL-3.0-or-later
// Full license text available in LICENSE file in repository root.

package web

import (
	"encoding/json"
	"errors"
	"mime/multipart"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

type fakeAdapters struct {
	ifaces []net.Interface
	addrs  map[string][]net.Addr
	err    error
}

func (f fakeAdapters) Interfaces() ([]net.Interface, error) { return f.ifaces, f.err }
func (f fakeAdapters) Addrs(iface net.Interface) ([]net.Addr, error) {
	return f.addrs[iface.Name], nil
}

func ipNet(s string) net.Addr {
	ip, n, err := net.ParseCIDR(s)
	if err != nil {
		panic(err)
	}
	return &net.IPNet{IP: ip, Mask: n.Mask}
}

func TestCheckLocalNetwork(t *testing.T) {
	up := net.FlagUp | net.FlagBroadcast
	src := fakeAdapters{
		ifaces: []net.Interface{
			{Name: "lo", Flags: net.FlagUp | net.FlagLoopback},
			{Name: "Wi-Fi", Flags: up},
			{Name: "Ethernet 2", Flags: 0}, // down
			{Name: "awdl0", Flags: up},     // link-local only: no real network
			{Name: "vEthernet (WSL)", Flags: up},
		},
		addrs: map[string][]net.Addr{
			"lo":              {ipNet("127.0.0.1/8")},
			"Wi-Fi":           {ipNet("fe80::1/64"), ipNet("192.168.1.20/24")},
			"Ethernet 2":      {ipNet("10.0.0.5/24")},
			"awdl0":           {ipNet("fe80::abcd/64"), ipNet("169.254.10.1/16")},
			"vEthernet (WSL)": {ipNet("172.20.0.1/20")},
		},
	}
	status := checkLocalNetwork(src)
	require.True(t, status.Connected)
	require.Equal(t, []NetworkAdapter{{Name: "Wi-Fi"}, {Name: "vEthernet (WSL)", Virtual: true}}, status.Adapters)
	require.NotEmpty(t, status.CheckedAt)

	offline := checkLocalNetwork(fakeAdapters{ifaces: src.ifaces[:1], addrs: src.addrs})
	require.False(t, offline.Connected)
	require.Empty(t, offline.Adapters)
	require.NotNil(t, offline.Adapters, "an empty list, not null, in the JSON")
}

func TestCheckLocalNetwork_UnknownCountsAsConnected(t *testing.T) {
	status := checkLocalNetwork(fakeAdapters{err: errors.New("permission denied")})
	require.True(t, status.Connected, "never claim offline without knowing")
}

func TestHandleNetworkStatus_NoAddresses(t *testing.T) {
	s := newTestServer(t)
	s.checkNetwork = func() NetworkStatus {
		return checkLocalNetwork(fakeAdapters{
			ifaces: []net.Interface{{Name: "Wi-Fi", Flags: net.FlagUp}},
			addrs:  map[string][]net.Addr{"Wi-Fi": {ipNet("192.168.1.20/24")}},
		})
	}
	rec := httptest.NewRecorder()
	s.handleNetworkStatus(rec, httptest.NewRequest(http.MethodPost, "/api/network-status", nil))
	require.Equal(t, http.StatusOK, rec.Code)
	require.NotContains(t, rec.Body.String(), "192.168", "adapter addresses must not leave the server")

	var status NetworkStatus
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &status))
	require.True(t, status.Connected)
	require.Equal(t, "Wi-Fi", status.Adapters[0].Name)
}

func TestHandleRecovery_BlockedWhileConnected(t *testing.T) {
	connected := func() NetworkStatus {
		return NetworkStatus{Connected: true, Adapters: []NetworkAdapter{{Name: "Wi-Fi"}}}
	}
	post := func(fields map[string]string) RecoveryResult {
		s := newTestServer(t)
		s.checkNetwork = connected
		req := multipartRequest(t, "/api/recover", lqnsUploads(), func(form *multipart.Writer) {
			for k, v := range fields {
				require.NoError(t, form.WriteField(k, v))
			}
		})
		rec := httptest.NewRecorder()
		s.handleRecovery(rec, req)
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		var result RecoveryResult
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &result))
		return result
	}

	blocked := post(map[string]string{"vaultId": fixtureLqnsVaultID})
	require.False(t, blocked.Success)
	require.True(t, blocked.NetworkBlocked)
	require.Contains(t, blocked.ErrorMessage, "Wi-Fi")
	require.Empty(t, blocked.EcdsaPrivateKey, "no key may be rebuilt while blocked")

	allowed := post(map[string]string{"vaultId": fixtureLqnsVaultID, "allowConnected": "true"})
	require.True(t, allowed.Success, allowed.ErrorMessage)
	require.False(t, allowed.NetworkBlocked)
}
