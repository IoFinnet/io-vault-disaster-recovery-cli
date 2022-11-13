package main

func toBitcoinWIF(privKey []byte, testNet, compressed bool) string {
	if compressed {
		// Append 0x01 to tell Bitcoin wallet to use compressed public keys
		privKey = append(privKey, []byte{0x01}...)
	}
	// Convert bytes to base-58 check encoded string with version 0x80 (mainnet) or 0xef (testnet)
	ver := uint8(0x80)
	if testNet {
		ver = 0xef
	}
	return b58checkencode(ver, privKey)
}
