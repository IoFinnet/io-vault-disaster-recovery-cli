module github.com/IoFinnet/io-vault-disaster-recovery-cli

go 1.14

require (
	github.com/binance-chain/go-sdk v1.2.4
	github.com/binance-chain/tss-lib v1.3.3
	github.com/decred/dcrd/dcrec/secp256k1 v1.0.3
	github.com/decred/dcrd/dcrec/secp256k1/v2 v2.0.0
	github.com/pkg/errors v0.9.1
	github.com/tyler-smith/go-bip39 v1.0.2
	golang.org/x/crypto v0.17.0
)

replace github.com/binance-chain/tss-lib => github.com/IoFinnet/threshlib v0.0.0-20240412064341-f3e687f63ba4

replace github.com/agl/ed25519 => github.com/bnb-chain/edwards25519 v0.0.0-20200305024217-f36fc4b53d43
