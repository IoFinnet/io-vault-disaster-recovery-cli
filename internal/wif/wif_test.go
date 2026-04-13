// Copyright (C) 2021 io finnet group, inc.
// SPDX-License-Identifier: AGPL-3.0-or-later
// Full license text available in LICENSE file in repository root.

package wif

import (
	"encoding/hex"
	"testing"
)

func TestToBitcoinWIF(t *testing.T) {
	// Reference strings from Bitcoin WIF / btcsuite btcutil tests.
	cases := []struct {
		name       string
		privHex    string
		testNet    bool
		compressed bool
		want       string
	}{
		{
			name:       "mainnet_uncompressed_btcsuite_vector",
			privHex:    "0c28fca386c7a227600b2fe50b7cae11ec86d3bf1fbe471be89827e19d72aa1d",
			testNet:    false,
			compressed: false,
			want:       "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ",
		},
		{
			name:       "testnet_compressed_btcsuite_vector",
			privHex:    "dda35a1488fb97b6eb3fe6e9ef2a25814e396fb5dc295fe994b96789b21a0398",
			testNet:    true,
			compressed: true,
			want:       "cV1Y7ARUr9Yx7BR55nTdnR7ZXNJphZtCCMBTEZBJe1hXt2kB684q",
		},
		{
			name:       "mainnet_compressed_one",
			privHex:    "0000000000000000000000000000000000000000000000000000000000000001",
			testNet:    false,
			compressed: true,
			want:       "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn",
		},
		{
			name:       "mainnet_uncompressed_one",
			privHex:    "0000000000000000000000000000000000000000000000000000000000000001",
			testNet:    false,
			compressed: false,
			want:       "5HpHagT65TZzG1PH3CSu63k8DbpvD8s5ip4nEB3kEsreAnchuDf",
		},
		{
			name:       "testnet_compressed_one",
			privHex:    "0000000000000000000000000000000000000000000000000000000000000001",
			testNet:    true,
			compressed: true,
			want:       "cMahea7zqjxrtgAbB7LSGbcQUr1uX1ojuat9jZodMN87JcbXMTcA",
		},
		{
			name:       "testnet_uncompressed_one",
			privHex:    "0000000000000000000000000000000000000000000000000000000000000001",
			testNet:    true,
			compressed: false,
			want:       "91avARGdfge8E4tZfYLoxeJ5sGBdNJQH4kvjJoQFacbgwmaKkrx",
		},
		{
			name:       "real_ecdsa_key_mainnet",
			privHex:    "2b8a34669aa76e0267442022b21bb36820b591881894acf6dbcf08169ff458fd",
			testNet:    false,
			compressed: true,
			want:       "KxgM4VnenWSPFesXaRoNfo5hG9y3agavzxxpbsdE65n9BDCAMgHA",
		},
		{
			name:       "real_ecdsa_key_testnet",
			privHex:    "2b8a34669aa76e0267442022b21bb36820b591881894acf6dbcf08169ff458fd",
			testNet:    true,
			compressed: true,
			want:       "cP3LXQnWDa8eR6LnxqcW37aktPGTF8gd517HiJ5jbCS9RxG2m8Vn",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			priv, err := hex.DecodeString(tc.privHex)
			if err != nil {
				t.Fatalf("hex.DecodeString: %v", err)
			}
			if len(priv) != 32 {
				t.Fatalf("private key length: got %d, want 32", len(priv))
			}
			got := string(ToBitcoinWIF(priv, tc.testNet, tc.compressed))
			if got != tc.want {
				t.Fatalf("ToBitcoinWIF(...) = %q, want %q", got, tc.want)
			}
		})
	}
}
