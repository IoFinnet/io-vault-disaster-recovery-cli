// Copyright (C) 2021 io finnet group, inc.
// SPDX-License-Identifier: AGPL-3.0-or-later
// Full license text available in LICENSE file in repository root.

package web

import (
	"encoding/json"
	"log"
	"net"
	"net/http"
	"sort"
	"strings"
	"time"
)

// NetworkStatus says whether this computer has an active network connection. It is worked out
// from the local network adapters only: the tool sends no traffic to find out, so it cannot tell
// whether a connection actually reaches the internet. Any adapter with a usable address counts.
type NetworkStatus struct {
	Connected bool             `json:"connected"`
	Adapters  []NetworkAdapter `json:"adapters"` // the active adapters; empty when offline
	CheckedAt string           `json:"checkedAt"`
}

// NetworkAdapter is one active network adapter. Names only: no addresses leave the server.
type NetworkAdapter struct {
	Name    string `json:"name"`
	Virtual bool   `json:"virtual"` // a best-effort guess that this is a VM, container or VPN adapter
}

// virtualAdapterHints are lower-case name fragments of common virtual adapters (hypervisors,
// container bridges, VPN tunnels). Matching is a hint for the user, never a reason to ignore one.
var virtualAdapterHints = []string{
	"vethernet", "hyper-v", "virtualbox", "vbox", "vmware", "vmnet", "docker", "veth", "br-", "virbr",
	"tailscale", "zerotier", "wireguard", "wg", "tun", "tap", "utun", "vpn", "loopback", "npcap",
}

// adapterSource is the subset of the net package checkLocalNetwork reads, so tests can supply
// their own adapters.
type adapterSource interface {
	Interfaces() ([]net.Interface, error)
	Addrs(iface net.Interface) ([]net.Addr, error)
}

type systemAdapters struct{}

func (systemAdapters) Interfaces() ([]net.Interface, error)          { return net.Interfaces() }
func (systemAdapters) Addrs(iface net.Interface) ([]net.Addr, error) { return iface.Addrs() }

// checkLocalNetwork lists the adapters that are up, are not loopback, and hold an address other
// systems could reach: any IPv4 or IPv6 address except loopback and link-local. A link-local-only
// adapter (169.254.x.x, fe80::) has no working network, so it does not count.
func checkLocalNetwork(src adapterSource) NetworkStatus {
	status := NetworkStatus{Adapters: []NetworkAdapter{}, CheckedAt: time.Now().UTC().Format(time.RFC3339)}
	ifaces, err := src.Interfaces()
	if err != nil {
		// Unknown is reported as connected: claiming "offline" without knowing would be unsafe.
		log.Printf("network check: could not list adapters: %v", err)
		status.Connected = true
		status.Adapters = append(status.Adapters, NetworkAdapter{Name: "Unknown (adapters could not be read)"})
		return status
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := src.Addrs(iface)
		if err != nil {
			continue
		}
		if !hasUsableAddress(addrs) {
			continue
		}
		status.Adapters = append(status.Adapters, NetworkAdapter{Name: iface.Name, Virtual: looksVirtual(iface.Name)})
	}
	sort.SliceStable(status.Adapters, func(i, j int) bool {
		if status.Adapters[i].Virtual != status.Adapters[j].Virtual {
			return !status.Adapters[i].Virtual // physical adapters first
		}
		return status.Adapters[i].Name < status.Adapters[j].Name
	})
	status.Connected = len(status.Adapters) > 0
	return status
}

func hasUsableAddress(addrs []net.Addr) bool {
	for _, addr := range addrs {
		var ip net.IP
		switch a := addr.(type) {
		case *net.IPNet:
			ip = a.IP
		case *net.IPAddr:
			ip = a.IP
		default:
			continue
		}
		if ip == nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
			continue
		}
		return true
	}
	return false
}

func looksVirtual(name string) bool {
	lower := strings.ToLower(name)
	for _, hint := range virtualAdapterHints {
		if strings.Contains(lower, hint) {
			return true
		}
	}
	return false
}

// handleNetworkStatus reports the local network status for the UI's offline indicator. It is a
// POST so the origin check applies: another website must not be able to read adapter names.
func (s *Server) handleNetworkStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	if err := json.NewEncoder(w).Encode(s.networkStatus()); err != nil {
		log.Printf("failed to encode network status: %v", err)
	}
}

// networkStatus is the server's view of the local network; tests replace checkNetwork.
func (s *Server) networkStatus() NetworkStatus {
	if s.checkNetwork != nil {
		return s.checkNetwork()
	}
	return checkLocalNetwork(systemAdapters{})
}
