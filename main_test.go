package main

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
)

const (
	mmV2 = "ridge scare utility perfect trial van inflict feel top dice present monitor always order charge door curious lobster quick guide obvious danger crisp cinnamon"
)

func TestTool_V2_c20x_List(t *testing.T) {
	// use the correct file path for tests
	address, sk, vaultIDs, err := runTool([]string{"./test-files/v2.json"},
		nil, nil, nil, nil, nil,
		mmV2)
	if !assert.NoError(t, err) {
		return
	}
	if !assert.Len(t, vaultIDs, 1) {
		return
	}
	if !assert.Equal(t, "yjanjbgmbrptwwa9i5v9c20x", vaultIDs[0]) {
		return
	}
	if !assert.Empty(t, address) {
		return
	}
	if !assert.Nil(t, sk) {
		return
	}
}

func TestTool_V2_c20x_Export(t *testing.T) {
	// use the correct file path for tests
	vaultID := "yjanjbgmbrptwwa9i5v9c20x"
	address, sk, vaultIDs, err := runTool([]string{"./test-files/v2.json"},
		&vaultID,
		nil, nil, nil, nil,
		mmV2)
	if !assert.NoError(t, err) {
		return
	}
	if !assert.Len(t, vaultIDs, 1) {
		return
	}
	if !assert.Equal(t, vaultID, vaultIDs[0]) {
		return
	}
	if !assert.Equal(t, "0x66e36b136fb8b2c98c72eec8ae02d531e526f454", address) {
		return
	}
	if !assert.Equal(t, "9ca4dc783e108938e81b06d76d7b74ec4488e1acc9c569eedfaf4c949c3531d7",
		hex.EncodeToString(sk.Bytes())) {
		return
	}
}
