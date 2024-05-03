module github.com/IoFinnet/io-vault-disaster-recovery-cli

go 1.17

require (
	github.com/binance-chain/tss-lib v1.3.3
	github.com/bnb-chain/go-sdk v1.3.2
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.3.0
	github.com/pkg/errors v0.9.1
	github.com/tyler-smith/go-bip39 v1.1.0
	golang.org/x/crypto v0.22.0
)

require (
	filippo.io/edwards25519 v1.1.0 // indirect
	github.com/agl/ed25519 v0.0.0-20200305024217-f36fc4b53d43 // indirect
	github.com/btcsuite/btcd/btcec/v2 v2.3.3 // indirect
	github.com/decred/dcrd/dcrec/edwards/v2 v2.0.3 // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/google/go-cmp v0.5.8 // indirect
	github.com/ipfs/go-log v1.0.5 // indirect
	github.com/ipfs/go-log/v2 v2.5.1 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/opentracing/opentracing-go v1.2.0 // indirect
	github.com/otiai10/primes v0.0.0-20210501021515-f1b2be525a11 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	go.uber.org/zap v1.27.0 // indirect
	golang.org/x/sys v0.19.0 // indirect
	google.golang.org/protobuf v1.34.0 // indirect
)

replace github.com/binance-chain/tss-lib => github.com/IoFinnet/threshlib v0.0.0-20240412064341-f3e687f63ba4

replace github.com/agl/ed25519 => github.com/bnb-chain/edwards25519 v0.0.0-20200305024217-f36fc4b53d43
