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
	ifaces   []net.Interface
	addrs    map[string][]net.Addr
	addrErrs map[string]error // per adapter: Addrs fails with this error
	err      error
}

func (f fakeAdapters) Interfaces() ([]net.Interface, error) { return f.ifaces, f.err }
func (f fakeAdapters) Addrs(iface net.Interface) ([]net.Addr, error) {
	if err := f.addrErrs[iface.Name]; err != nil {
		return nil, err
	}
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
			{Name: "awdl0", Flags: up},     // link-local only and not running: no link
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

// An active adapter whose addresses cannot be read counts as connected, like an unreadable list.
func TestCheckLocalNetwork_UnreadableAddressesCountAsConnected(t *testing.T) {
	denied := errors.New("permission denied")
	status := checkLocalNetwork(fakeAdapters{
		ifaces: []net.Interface{
			{Name: "lo", Flags: net.FlagUp | net.FlagLoopback},
			{Name: "Wi-Fi", Flags: net.FlagUp | net.FlagRunning},
			{Name: "Ethernet 2", Flags: 0},          // down: never inspected
			{Name: "Ethernet 3", Flags: net.FlagUp}, // read, but no usable address
			{Name: "Tailscale", Flags: net.FlagUp},  // unreadable, and looks virtual
		},
		addrs:    map[string][]net.Addr{"Ethernet 3": {}},
		addrErrs: map[string]error{"lo": denied, "Wi-Fi": denied, "Ethernet 2": denied, "Tailscale": denied},
	})
	require.True(t, status.Connected, "never claim offline without knowing")
	require.Equal(t, []NetworkAdapter{
		{Name: "Wi-Fi (addresses could not be read)"},
		{Name: "Tailscale (addresses could not be read)", Virtual: true},
	}, status.Adapters)
}

// A running adapter with only link-local addresses can still reach hosts on its link, so it
// counts; a point-to-point tunnel with only an fe80:: address does not.
func TestCheckLocalNetwork_LinkLocalOnly(t *testing.T) {
	running := net.FlagUp | net.FlagRunning | net.FlagBroadcast | net.FlagMulticast
	status := checkLocalNetwork(fakeAdapters{
		ifaces: []net.Interface{
			{Name: "Ethernet (direct cable)", Flags: running},
			{Name: "en5", Flags: running},
			{Name: "utun3", Flags: net.FlagUp | net.FlagRunning | net.FlagPointToPoint | net.FlagMulticast},
			{Name: "awdl0", Flags: net.FlagUp | net.FlagBroadcast}, // up but not running
			{Name: "Ethernet 9", Flags: running},
		},
		addrs: map[string][]net.Addr{
			"Ethernet (direct cable)": {ipNet("169.254.10.1/16")},
			"en5":                     {ipNet("fe80::1/64")},
			"utun3":                   {ipNet("fe80::abcd/64")},
			"awdl0":                   {ipNet("fe80::abcd/64")},
			"Ethernet 9":              {ipNet("0.0.0.0/0"), ipNet("::1/128")}, // unspecified and loopback only
		},
	})
	require.True(t, status.Connected)
	require.Equal(t, []NetworkAdapter{{Name: "Ethernet (direct cable)"}, {Name: "en5"}}, status.Adapters)

	tunnelOnly := checkLocalNetwork(fakeAdapters{
		ifaces: []net.Interface{{Name: "utun0", Flags: net.FlagUp | net.FlagRunning | net.FlagPointToPoint}},
		addrs:  map[string][]net.Addr{"utun0": {ipNet("fe80::1/64")}},
	})
	require.False(t, tunnelOnly.Connected, "a tunnel's link-local address alone must not mark every Mac connected")

	routedTunnel := checkLocalNetwork(fakeAdapters{
		ifaces: []net.Interface{{Name: "utun0", Flags: net.FlagUp | net.FlagRunning | net.FlagPointToPoint}},
		addrs:  map[string][]net.Addr{"utun0": {ipNet("fe80::1/64"), ipNet("100.64.0.2/32")}},
	})
	require.True(t, routedTunnel.Connected, "a tunnel with a routable address still counts")
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

// The computer can connect while the uploads are processed, so the check runs again right before
// the key is rebuilt.
func TestHandleRecovery_RechecksNetworkBeforeReconstruction(t *testing.T) {
	post := func(fields map[string]string) (RecoveryResult, int) {
		s := newTestServer(t)
		calls := 0
		s.checkNetwork = func() NetworkStatus {
			calls++
			if calls == 1 {
				return NetworkStatus{Adapters: []NetworkAdapter{}} // offline at the start
			}
			return NetworkStatus{Connected: true, Adapters: []NetworkAdapter{{Name: "Wi-Fi"}}}
		}
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
		return result, calls
	}

	blocked, calls := post(map[string]string{"vaultId": fixtureLqnsVaultID})
	require.Equal(t, 2, calls)
	require.False(t, blocked.Success)
	require.True(t, blocked.NetworkBlocked)
	require.Contains(t, blocked.ErrorMessage, "Wi-Fi")
	require.Empty(t, blocked.EcdsaPrivateKey, "no key may be rebuilt once the computer connects")
	require.Empty(t, blocked.EddsaPrivateKey)

	allowed, _ := post(map[string]string{"vaultId": fixtureLqnsVaultID, "allowConnected": "true"})
	require.True(t, allowed.Success, allowed.ErrorMessage)
	require.False(t, allowed.NetworkBlocked)
}
