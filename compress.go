package main

import (
	"bytes"
	"compress/flate"
	"fmt"
	"io"
)

// DEFLATE (customized)

// deflateCommonJSONDict is a custom dictionary for the DEFLATE algorithm based on our JSON save data format.
// This reduces the size of the compressed data (in some cases, significantly).
// DO NOT CHANGE THIS VALUE WITHOUT MIGRATING SAVED DATA PROPERLY!
const deflateCommonJSONDict = `null` +
	`{"PaillierSK":{"N":6922045424785223,"LambdaN":4363699717840427,"PhiN":1145683160139719},"NTildei":8522668679230366,"H1i":431112616415448,"H2i":2218581434585855,"Alpha":1644458411253359,"Beta":2055026955915508,"P":1241053165406178,"Q":1516049695813965,"Xi":8108379843691545,"ShareID":332537562,"Ks":[8215999875339097],"NTildej":[8884582175310771],"H1j":[4444713407350296],"H2j":[7785566466619086,3388458350150109],"BigXj":[{"Curve":"secp256k1","Coords":[1159753063359249,8401050585979724]},{"Curve":"secp256k1","Coords":[4204142946914243,1580053746046931]}],"PaillierPKs":[{"N":6991977320107385},{"N":1990415854994626}],"ECDSAPub":{"Curve":"secp256k1","Coords":[4388167466892256,5461155207642833]}}` +
	`{"Xi":3754872620939198,"ShareID":1643074317,"Ks":[2807299711782590,4735268842394955],"BigXj":[{"Curve":"ed25519","Coords":[5485415139763324,743952773955764]},{"Curve":"ed25519","Coords":[8068345193554698,8977361460270075]}],"EDDSAPub":{"Curve":"ed25519","Coords":[8317261857323617,796509558082006]}}` +
	`secp256k1` + `nist256p1` + `ed25519` + `P384` + `P521` +
	`Anomalous` + `M-221` + `E-222` + `M-511` + `E-521` + `NIST P-224` + `Curve1174` + `curve25519` + `BN(2,254)` + `brainpoolP256t1` + `ANSSI` + `FRP256v1` + `NIST P-256` + `E-382` + `M-383` + `Curve383187` + `brainpoolP384t1` + `NIST P-384` + `Curve41417` + `Ed448-Goldilocks` +
	`LocalSecrets` + `LocalPreParams`

// inflateSaveDataJSON decompresses TSS save data in JSON format using the DEFLATE algorithm using a custom dictionary.
func inflateSaveDataJSON(compressed []byte) ([]byte, error) {
	reader := flate.NewReaderDict(bytes.NewReader(compressed), []byte(deflateCommonJSONDict))
	decompressed, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to read from flate reader: %v", err)
	}
	return decompressed, reader.Close()
}
