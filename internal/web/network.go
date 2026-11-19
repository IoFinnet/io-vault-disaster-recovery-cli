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
// whether a connection actually reaches the internet. See checkLocalNetwork for what counts.
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

// checkLocalNetwork lists the adapters that are up, are not loopback, and could reach another
// system: any adapter holding an IPv4 or IPv6 address other than loopback, unspecified or
// link-local; or a running adapter whose only addresses are link-local (169.254.x.x, fe80::),
// since those still reach other hosts on the same link, such as a laptop cabled to another
// machine. Point-to-point adapters are not counted for link-local addresses alone: tunnels such as
// macOS utun always carry an fe80:: address and reach nothing until a VPN routes through them.
// An adapter whose addresses cannot be read is counted, like an unreadable adapter list.
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
			// An active adapter we cannot inspect may be connected; as above, never assume offline.
			log.Printf("network check: could not read the addresses of adapter %s: %v", iface.Name, err)
			status.Adapters = append(status.Adapters, NetworkAdapter{
				Name:    iface.Name + " (addresses could not be read)",
				Virtual: looksVirtual(iface.Name),
			})
			continue
		}
		routable, linkLocal := classifyAddresses(addrs)
		linkLocalReachable := linkLocal && iface.Flags&net.FlagRunning != 0 && iface.Flags&net.FlagPointToPoint == 0
		if !routable && !linkLocalReachable {
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

// classifyAddresses reports whether addrs include a routable address (anything but loopback,
// unspecified and link-local), and whether they include a link-local unicast address.
func classifyAddresses(addrs []net.Addr) (routable, linkLocal bool) {
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
		switch {
		case ip == nil || ip.IsLoopback() || ip.IsUnspecified() || ip.IsLinkLocalMulticast():
			continue
		case ip.IsLinkLocalUnicast():
			linkLocal = true
		default:
			routable = true
		}
	}
	return routable, linkLocal
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
