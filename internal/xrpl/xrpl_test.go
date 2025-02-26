// Copyright (C) 2021 io finnet group, inc.
// SPDX-License-Identifier: AGPL-3.0-or-later
// Full license text available in LICENSE file in repository root.

package xrpl

import (
	"encoding/hex"
	"testing"
)

func TestDeriveXRPLAddress(t *testing.T) {
	tests := []struct {
		name       string
		pubKeyHex  string
		wantAddr   string
		wantErr    bool
	}{
		{
			name:      "EdDSA public key 1",
			pubKeyHex: "c4c75ac0852c26164819f22bf144264df457a30a17926896f23ae81d3bf3f712",
			wantAddr:  "rQKFCzntQegDZNfgCa48pREVdikKyRdHvj",
			wantErr:   false,
		},
		{
			name:      "EdDSA public key 2",
			pubKeyHex: "892bfcf7c7370b060a109e53aea6352f10ac260268ac55770c7665efc0a19dd9",
			wantAddr:  "rfpGNkj3spJxm1Ag3D8SgPwGnV2LMA8MrB",
			wantErr:   false,
		},
		{
			name:      "Empty public key",
			pubKeyHex: "",
			wantAddr:  "",
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var pubKey []byte
			var err error
			
			if tt.pubKeyHex != "" {
				pubKey, err = hex.DecodeString(tt.pubKeyHex)
				if err != nil {
					t.Fatalf("Failed to decode hex public key: %v", err)
				}
				
				// Debug information
				t.Logf("Input pubKey hex: %s", tt.pubKeyHex)
				t.Logf("Input pubKey bytes: %v", pubKey)
			}
			
			// Add more debug info about the key format
			if tt.pubKeyHex != "" {
				t.Logf("Public key length: %d bytes", len(pubKey))
				
				// Format with ED25519 prefix for debugging
				formattedPubKey := append([]byte{0xED}, pubKey...)
				t.Logf("Formatted pubKey with ED prefix: %v", formattedPubKey)
				t.Logf("Formatted pubKey length: %d bytes", len(formattedPubKey))
			}
			
			gotAddr, err := DeriveXRPLAddress(pubKey)
			
			if (err != nil) != tt.wantErr {
				t.Errorf("DeriveXRPLAddress() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			
			if !tt.wantErr {
				if gotAddr != tt.wantAddr {
					t.Errorf("DeriveXRPLAddress() = %v, want %v", gotAddr, tt.wantAddr)
					
					// Additional debug info for address comparison
					t.Logf("Address length: got=%d, want=%d", len(gotAddr), len(tt.wantAddr))
					t.Logf("First 5 chars: got=%s, want=%s", gotAddr[:5], tt.wantAddr[:5])
				} else {
					t.Logf("Successfully derived address: %s", gotAddr)
				}
			}
		})
	}
}

func TestGenerateFamilySeed(t *testing.T) {
	tests := []struct {
		name          string
		privateKeyHex string
		wantErr       bool
	}{
		{
			name:          "Valid private key",
			privateKeyHex: "1ACAAEDECE405B2A958212629E16F2EB46B153EEE94CDD350FDEFF52795525B7",
			wantErr:       false,
		},
		{
			name:          "Empty private key",
			privateKeyHex: "",
			wantErr:       true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var privateKey []byte
			var err error
			
			if tt.privateKeyHex != "" {
				privateKey, err = hex.DecodeString(tt.privateKeyHex)
				if err != nil {
					t.Fatalf("Failed to decode hex private key: %v", err)
				}
			}
			
			gotSeed, err := GenerateFamilySeed(privateKey)
			
			if (err != nil) != tt.wantErr {
				t.Errorf("GenerateFamilySeed() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			
			if !tt.wantErr && len(gotSeed) == 0 {
				t.Errorf("GenerateFamilySeed() returned empty seed")
			}
		})
	}
}

func TestIsValidXRPAddress(t *testing.T) {
	tests := []struct {
		name    string
		address string
		want    bool
	}{
		{
			name:    "Valid address 1",
			address: "rQKFCzntQegDZNfgCa48pREVdikKyRdHvj",
			want:    true,
		},
		{
			name:    "Valid address 2",
			address: "rfpGNkj3spJxm1Ag3D8SgPwGnV2LMA8MrB",
			want:    true,
		},
		{
			name:    "Invalid prefix",
			address: "xHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh",
			want:    false,
		},
		{
			name:    "Too short",
			address: "rHb9",
			want:    false,
		},
		{
			name:    "Too long",
			address: "rHb9CJAWyB4rj91VRWn96DkukG4bwdtyThXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
			want:    false,
		},
		{
			name:    "Empty string",
			address: "",
			want:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isValidXRPAddress(tt.address); got != tt.want {
				t.Errorf("isValidXRPAddress() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsValidXRPAmount(t *testing.T) {
	tests := []struct {
		name   string
		amount string
		want   bool
	}{
		{
			name:   "Valid amount",
			amount: "100",
			want:   true,
		},
		{
			name:   "Valid decimal amount",
			amount: "0.001",
			want:   true,
		},
		{
			name:   "Negative amount",
			amount: "-10",
			want:   false,
		},
		{
			name:   "Empty amount",
			amount: "",
			want:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isValidXRPAmount(tt.amount); got != tt.want {
				t.Errorf("isValidXRPAmount() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestHandleTransaction(t *testing.T) {
	// Create a valid mock private key for testing
	mockPrivateKey := make([]byte, 32)
	// Set the first byte to a non-zero value to avoid "zero or negative scalar" error
	mockPrivateKey[0] = 1
	
	tests := []struct {
		name        string
		privateKey  []byte
		destination string
		amount      string
		testnet     bool
		wantErr     bool
	}{
		{
			name:        "Valid transaction parameters",
			privateKey:  mockPrivateKey,
			destination: "rQKFCzntQegDZNfgCa48pREVdikKyRdHvj",
			amount:      "10.5",
			testnet:     false,
			wantErr:     false,
		},
		{
			name:        "Invalid destination",
			privateKey:  mockPrivateKey,
			destination: "invalid",
			amount:      "10",
			testnet:     false,
			wantErr:     true,
		},
		{
			name:        "Invalid amount",
			privateKey:  mockPrivateKey,
			destination: "rQKFCzntQegDZNfgCa48pREVdikKyRdHvj",
			amount:      "-10",
			testnet:     false,
			wantErr:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := HandleTransaction(tt.privateKey, tt.destination, tt.amount, tt.testnet)
			if (err != nil) != tt.wantErr {
				t.Errorf("HandleTransaction() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
