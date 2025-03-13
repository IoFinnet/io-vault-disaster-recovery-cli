// Copyright (C) 2021 io finnet group, inc.
// SPDX-License-Identifier: AGPL-3.0-or-later
// Full license text available in LICENSE file in repository root.

package xrpl

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/btcsuite/btcd/btcutil/base58"
	"golang.org/x/crypto/ripemd160"
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
				
				// Add ED25519 prefix for debugging
				formattedPubKey := append([]byte{0xED}, pubKey...)
				t.Logf("Formatted pubKey with ED prefix: %x", formattedPubKey)
				t.Logf("Formatted pubKey length: %d bytes", len(formattedPubKey))
				
				// Hash the formatted public key for debugging
				sha256Hash := sha256.Sum256(formattedPubKey)
				t.Logf("SHA-256 hash of formatted pubKey: %x", sha256Hash)
				
				// RIPEMD-160 hash for debugging
				ripemd160Hasher := ripemd160.New()
				ripemd160Hasher.Write(sha256Hash[:])
				ripemd160Hash := ripemd160Hasher.Sum(nil)
				t.Logf("RIPEMD-160 hash: %x", ripemd160Hash)
				
				// Prefixed hash for debugging
				prefixedHash := append([]byte{AccountIDPrefix}, ripemd160Hash...)
				t.Logf("Prefixed hash (with 0x00): %x", prefixedHash)
				
				// Checksum for debugging
				firstHash := sha256.Sum256(prefixedHash)
				secondHash := sha256.Sum256(firstHash[:])
				checksum := secondHash[:4]
				t.Logf("Checksum: %x", checksum)
				
				// Final bytes for base58 encoding
				addressBytes := append(prefixedHash, checksum...)
				t.Logf("Final bytes for base58: %x", addressBytes)
				
				// Raw base58 encoding with standard alphabet
				rawBase58 := base58.Encode(addressBytes)
				t.Logf("Standard base58 encoding: %s", rawBase58)
				
				// XRPL base58 encoding
				xrplBase58 := encodeBase58WithXRPLAlphabet(addressBytes)
				t.Logf("XRPL base58 encoding: %s", xrplBase58)
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
					if len(gotAddr) >= 5 && len(tt.wantAddr) >= 5 {
						t.Logf("First 5 chars: got=%s, want=%s", gotAddr[:5], tt.wantAddr[:5])
					} else {
						t.Logf("Address too short for comparison: got=%s, want=%s", gotAddr, tt.wantAddr)
					}
				} else {
					t.Logf("Successfully derived address: %s", gotAddr)
				}
			}
		})
	}
}
