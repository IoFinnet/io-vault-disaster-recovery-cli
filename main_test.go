package main

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
)

// Test fixture mnemonics. Used only for this purpose.
const (
	mmI  = "season pole chronic surround fiber stumble remove artwork muffin apart limit vacuum horror above donkey olympic earn dizzy addict gym animal leopard before unfair"
	mmL  = "casual gallery jump mad claw curve portion enrich oyster calm spoon flash hat soft dizzy example exile large provide smart magnet raven nurse prison"
	mmM  = "decade explain repeat popular pigeon sail atom enhance toy awake breeze draw focus desert movie skull news inherit cruel case start film used unit"
	mmV2 = "ridge scare utility perfect trial van inflict feel top dice present monitor always order charge door curious lobster quick guide obvious danger crisp cinnamon"
)

func TestTool_V2_List(t *testing.T) {
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

func TestTool_V2_Export_c20x(t *testing.T) {
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

func TestTool_V1_IL_List(t *testing.T) {
	// use the correct file path for tests
	address, sk, vaultIDs, err := runTool([]string{"./test-files/i.json", "./test-files/l.json"},
		nil, nil, nil, nil, nil,
		mmI, mmL)
	if !assert.NoError(t, err) {
		return
	}
	if !assert.Len(t, vaultIDs, 6) {
		return
	}
	if !assert.Equal(t, []string{
		"clujhtm9d0013wc3xso1b2m0k", "clujmawnb001j173x9a2c0x47", "clujn9hhr001u173xiv9gfme6", "clujnasrf001x173xjxtcwzeq", "clul2s3f70008yf3x7mada0gb", "clur52dfl0001vc3xlbdy1d7p",
	}, vaultIDs) {
		return
	}
	if !assert.Empty(t, address) {
		return
	}
	if !assert.Nil(t, sk) {
		return
	}
}

func TestTool_V1_IL_Export_m0k(t *testing.T) {
	// use the correct file path for tests
	vaultID := "clujhtm9d0013wc3xso1b2m0k"
	address, sk, vaultIDs, err := runTool([]string{"./test-files/i.json", "./test-files/l.json"},
		&vaultID,
		nil, nil, nil, nil,
		mmI, mmL)
	if !assert.NoError(t, err) {
		return
	}
	if !assert.Len(t, vaultIDs, 1) {
		return
	}
	if !assert.Equal(t, vaultID, vaultIDs[0]) {
		return
	}
	if !assert.Equal(t, "0x66ee83f83002b01459b750233f7b21744e679182", address) {
		return
	}
	if !assert.Equal(t, "7d3c016f339f8cc797ee35502a5c93416d47bdd04360d22ea4fcaf85cec229b3",
		hex.EncodeToString(sk.Bytes())) {
		return
	}
}

func TestTool_V1_ILM_List(t *testing.T) {
	// use the correct file path for tests
	address, sk, vaultIDs, err := runTool([]string{"./test-files/i.json", "./test-files/m.json", "./test-files/l.json"},
		nil, nil, nil, nil, nil,
		mmI, mmM, mmL)
	if !assert.NoError(t, err) {
		return
	}
	if !assert.Len(t, vaultIDs, 6) {
		return
	}
	if !assert.Equal(t, []string{
		"clujhtm9d0013wc3xso1b2m0k", "clujmawnb001j173x9a2c0x47", "clujn9hhr001u173xiv9gfme6", "clujnasrf001x173xjxtcwzeq", "clul2s3f70008yf3x7mada0gb", "clur52dfl0001vc3xlbdy1d7p",
	}, vaultIDs) {
		return
	}
	if !assert.Empty(t, address) {
		return
	}
	if !assert.Nil(t, sk) {
		return
	}
}

func TestTool_V1_ILM_Export_m0k(t *testing.T) {
	// use the correct file path for tests
	vaultID := "clujhtm9d0013wc3xso1b2m0k"
	address, sk, vaultIDs, err := runTool([]string{"./test-files/i.json", "./test-files/m.json", "./test-files/l.json"},
		&vaultID,
		nil, nil, nil, nil,
		mmI, mmM, mmL)
	if !assert.NoError(t, err) {
		return
	}
	if !assert.Len(t, vaultIDs, 1) {
		return
	}
	if !assert.Equal(t, vaultID, vaultIDs[0]) {
		return
	}
	if !assert.Equal(t, "0x66ee83f83002b01459b750233f7b21744e679182", address) {
		return
	}
	if !assert.Equal(t, "7d3c016f339f8cc797ee35502a5c93416d47bdd04360d22ea4fcaf85cec229b3",
		hex.EncodeToString(sk.Bytes())) {
		return
	}
}
