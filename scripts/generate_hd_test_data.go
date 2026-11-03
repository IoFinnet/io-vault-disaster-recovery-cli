//go:build ignore

// This script documents the HD test data generation process.
// Due to vendor mode restrictions, it cannot be run directly.
// Instead, the test files have been pre-generated.
//
// Test files:
// - test-files/hd_test_addresses.csv (input CSV for integration tests)
//
// The test vectors use the following master keys (matching tss-lib test vectors):
//
// ECDSA (secp256k1):
//   Master SK: e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35
//   Chain code: 873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508
//   Master PK: 0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2
//   xpub: xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8
//
// EdDSA (Edwards25519):
//   Master SK: 9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60
//   Chain code: 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
//   Master PK: 557a7032255934a29ed3f05862b1cbbfb264a08de7bb51114a4526fc177d466f
//   xpub: xpub661MyMwAqRbcEZ6F7ZYpZTTdD8ToN2UCzBt5jjXxBm3y4jwbUJncoqTbB4zY28NpWEvDswPSAoYigFG6PAhzMZ3SMDz4KNaQvKzUtaEqJuL

package main

import "fmt"

func main() {
	fmt.Println("HD Test Data Documentation")
	fmt.Println("==========================")
	fmt.Println()
	fmt.Println("Test data has been pre-generated in test-files/hd_test_addresses.csv")
	fmt.Println()
	fmt.Println("The CSV contains test cases for:")
	fmt.Println("  - ECDSA/secp256k1: 3 test cases at paths m/0, m/44/0/0, m/44/60/0/0/0")
	fmt.Println("  - EdDSA/Edwards25519: 2 test cases at paths m/0, m/44/501/0/0")
	fmt.Println()
	fmt.Println("Derivation tests in internal/hd/derive_tss_test.go verify compatibility")
	fmt.Println("with tss-lib HD derivation for both algorithm/curve combinations.")
}
