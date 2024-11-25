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

	// James test case mnemonics
	mmNewBvn = "domain damp hill depth label eye erode dutch impulse betray floor donate bonus hover bitter ring unfold poet identify capital combine question profit april"
	mmNewX2q = "found midnight praise exhibit weather neutral inmate strong grass famous blind pet frozen shock avocado ring fringe planet opera license stand coil beauty capable"
	mmNewU44 = "aerobic foam smooth immune card tragic window myth planet notice piece agree add target tortoise weather kite track spot dish dignity twice gadget spell"

	// Single Signer test case mnemonics
	mmNewSingle = "jacket zone rotate merry forward paper cruel forget train prevent teach bitter lumber razor uncle stairs finger chief curtain render tray tower odor garbage"
)

func TestTool_New_V2_List(t *testing.T) {
	files := []VaultsDataFile{
		{File: "./test-files/new_bvn.json", Mnemonics: mmNewBvn},
		{File: "./test-files/new_x2q.json", Mnemonics: mmNewX2q},
		{File: "./test-files/new_u44.json", Mnemonics: mmNewU44},
	}

	// use the correct file path for tests
	address, ecSK, edSK, vaultFormData, err := runTool(files, nil, nil, nil, nil, nil)
	if !assert.NoError(t, err) {
		return
	}
	if !assert.Len(t, vaultFormData, 14) {
		return
	}

	vaultIDs := vaultIdsFromFormData(vaultFormData)
	if !assert.Equal(t,
		[]string{
			"a70uaean4isi6aci8zzky970",
			"afpuzaa5j3k7wyjfgkuvbcxz",
			"bfc8uksrk5zuxihufj4m8dkt",
			"d1rqfhghbr1qy819iym5dgyv",
			"dfqyrx0f7vevbjx9o5yrg7gw",
			"e0wspn90rz8vnngv0kdklaog",
			"ejrye15wiew2201f3fahho8k",
			"iesd46upmcrwnu0qojph9hst",
			"liw3bn8yqykgh96uort11knz",
			"nbpxb6hmupk1ygcl53jf9zg5",
			"ngo46g83iug985q3fxyhsp4w",
			"prd15bna3h9oxoo04dc4cn1p",
			"yz5x2a7zhwwt7r0lv4gklqns",
			"zbgtamgot1f6u51kt6bsn5qr",
		}, vaultIDs) {
		return
	}
	if !assert.Empty(t, address) {
		return
	}
	if !assert.Nil(t, ecSK) || !assert.Nil(t, edSK) {
		return
	}
}

func TestTool_New_V2_Export_lqns(t *testing.T) {
	// use the correct file path for tests
	vaultID := "yz5x2a7zhwwt7r0lv4gklqns"

	files := []VaultsDataFile{
		{File: "./test-files/new_bvn.json", Mnemonics: mmNewBvn},
		{File: "./test-files/new_x2q.json", Mnemonics: mmNewX2q},
		{File: "./test-files/new_u44.json", Mnemonics: mmNewU44},
	}

	address, ecSK, edSK, vaultsFormData, err := runTool(files, &vaultID, nil, nil, nil, nil)
	if !assert.NoError(t, err) {
		return
	}
	if !assert.Len(t, vaultsFormData, 1) {
		return
	}
	if !assert.Equal(t, vaultID, vaultsFormData[0].VaultID) {
		return
	}
	if !assert.Equal(t, "0x620ac72121234f1b313bd4e8b78c81323502679a", address) {
		return
	}
	if !assert.Equal(t, "4cc05b1d3216da8ef91729744159019b25ea1ed5932e387199f1de6ff6667ac2",
		hex.EncodeToString(ecSK.Bytes())) {
		return
	}
	if !assert.Equal(t, "0e6f0e12d72483d32255000d01242fa4e179b9bbfa060de26cfb9c84e1d02d9e",
		hex.EncodeToString(edSK.Bytes())) {
		return
	}
}

func TestTool_NewSingle_V2_List(t *testing.T) {
	files := []VaultsDataFile{
		{File: "./test-files/new_single.json", Mnemonics: mmNewSingle},
	}
	// use the correct file path for tests
	address, _, edSK, vaultFormData, err := runTool(files, nil, nil, nil, nil, nil)
	if !assert.NoError(t, err) {
		return
	}
	if !assert.Len(t, vaultFormData, 1) {
		return
	}
	vaultIDs := vaultIdsFromFormData(vaultFormData)
	if !assert.Contains(t, vaultIDs, "phrot42ltzawmn7nrm7mqvl5", "vaults must contain expected vaultId qvl5") {
		return
	}
	if !assert.Empty(t, address) {
		return
	}
	if !assert.Nil(t, edSK) {
		return
	}
}

func TestTool_NewSingle_V2_List_BadMnemonic(t *testing.T) {
	files := []VaultsDataFile{
		{File: "./test-files/new_single.json", Mnemonics: mmV2},
	}
	// use the correct file path for tests
	_, _, _, _, err := runTool(files, nil, nil, nil, nil, nil)
	if !assert.Error(t, err) {
		return
	}
}

func TestTool_NewSingle_V2_Export_qvl5(t *testing.T) {
	// use the correct file path for tests
	vaultID := "phrot42ltzawmn7nrm7mqvl5"

	files := []VaultsDataFile{
		{File: "./test-files/new_single.json", Mnemonics: mmNewSingle},
	}
	_, _, edSK, vaultsFormData, err := runTool(files, &vaultID, nil, nil, nil, nil)
	if !assert.NoError(t, err) {
		return
	}
	if !assert.Len(t, vaultsFormData, 1) {
		return
	}
	if !assert.Equal(t, vaultID, vaultsFormData[0].VaultID) {
		return
	}
	if !assert.Equal(t, "04523b4b19d426517fb20b51935bc969900e016d26da0a3357f4cb1af57d8e44",
		hex.EncodeToString(edSK.Bytes())) {
		return
	}
}

func TestTool_NewSingle_V2_Export_qvl5_BadMnemonic(t *testing.T) {
	// use the correct file path for tests
	vaultID := "phrot42ltzawmn7nrm7mqvl5"

	files := []VaultsDataFile{
		{File: "./test-files/new_single.json", Mnemonics: mmV2},
	}
	_, _, _, _, err := runTool(files, &vaultID, nil, nil, nil, nil)
	if !assert.Error(t, err) {
		return
	}
}

func TestTool_Legacy_V2_List(t *testing.T) {
	files := []VaultsDataFile{
		{File: "./test-files/v2.json", Mnemonics: mmV2},
	}

	// use the correct file path for tests
	address, ecSK, edSK, vaultsFormData, err := runTool(files, nil, nil, nil, nil, nil)
	if !assert.NoError(t, err) {
		return
	}
	if !assert.Len(t, vaultsFormData, 1) {
		return
	}
	if !assert.Equal(t, "yjanjbgmbrptwwa9i5v9c20x", vaultsFormData[0].VaultID) {
		return
	}
	if !assert.Empty(t, address) {
		return
	}
	if !assert.Nil(t, ecSK) || !assert.Nil(t, edSK) {
		return
	}
}

func TestTool_Legacy_V2_Export_c20x(t *testing.T) {
	// use the correct file path for tests
	vaultID := "yjanjbgmbrptwwa9i5v9c20x"

	files := []VaultsDataFile{
		{File: "./test-files/v2.json", Mnemonics: mmV2},
	}

	address, ecSK, edSK, vaultsFormData, err := runTool(files, &vaultID, nil, nil, nil, nil)
	if !assert.NoError(t, err) {
		return
	}
	if !assert.Len(t, vaultsFormData, 1) {
		return
	}
	if !assert.Equal(t, vaultID, vaultsFormData[0].VaultID) {
		return
	}
	if !assert.Equal(t, "0x66e36b136fb8b2c98c72eec8ae02d531e526f454", address) {
		return
	}
	if !assert.Equal(t, "9ca4dc783e108938e81b06d76d7b74ec4488e1acc9c569eedfaf4c949c3531d7",
		hex.EncodeToString(ecSK.Bytes())) {
		return
	}
	// no EdDSA key for this vault
	if !assert.Nil(t, edSK) {
		return
	}
}

func TestTool_Legacy_V1_IL_List(t *testing.T) {
	// use the correct file path for tests
	files := []VaultsDataFile{
		{File: "./test-files/i.json", Mnemonics: mmI},
		{File: "./test-files/l.json", Mnemonics: mmL},
	}

	address, ecSK, edSK, vaultsFormData, err := runTool(files, nil, nil, nil, nil, nil)
	if !assert.NoError(t, err) {
		return
	}
	if !assert.Len(t, vaultsFormData, 6) {
		return
	}
	vaultIDs := vaultIdsFromFormData(vaultsFormData)
	if !assert.Equal(t, []string{
		"clujhtm9d0013wc3xso1b2m0k", "clujmawnb001j173x9a2c0x47", "clujn9hhr001u173xiv9gfme6", "clujnasrf001x173xjxtcwzeq", "clul2s3f70008yf3x7mada0gb", "clur52dfl0001vc3xlbdy1d7p",
	}, vaultIDs) {
		return
	}
	if !assert.Empty(t, address) {
		return
	}
	if !assert.Nil(t, ecSK) || !assert.Nil(t, edSK) {
		return
	}
}

func TestTool_Legacy_V1_IL_Export_m0k(t *testing.T) {
	// use the correct file path for tests
	vaultID := "clujhtm9d0013wc3xso1b2m0k"

	files := []VaultsDataFile{
		{File: "./test-files/i.json", Mnemonics: mmI},
		{File: "./test-files/l.json", Mnemonics: mmL},
	}

	address, ecSK, edSK, vaultFormData, err := runTool(files, &vaultID, nil, nil, nil, nil)

	if !assert.NoError(t, err) {
		return
	}
	vaultIDs := vaultIdsFromFormData(vaultFormData)
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
		hex.EncodeToString(ecSK.Bytes())) {
		return
	}
	// no EdDSA key for this vault
	if !assert.Nil(t, edSK) {
		return
	}
}

func TestTool_Legacy_V1_ILM_List(t *testing.T) {
	// use the correct file path for tests
	files := []VaultsDataFile{
		{File: "./test-files/i.json", Mnemonics: mmI},
		{File: "./test-files/m.json", Mnemonics: mmM},
		{File: "./test-files/l.json", Mnemonics: mmL},
	}

	address, ecSK, edSK, vaultsFormData, err := runTool(files, nil, nil, nil, nil, nil)
	if !assert.NoError(t, err) {
		return
	}
	if !assert.Len(t, vaultsFormData, 6) {
		return
	}
	vaultIDs := vaultIdsFromFormData(vaultsFormData)
	if !assert.Equal(t, []string{
		"clujhtm9d0013wc3xso1b2m0k", "clujmawnb001j173x9a2c0x47", "clujn9hhr001u173xiv9gfme6", "clujnasrf001x173xjxtcwzeq", "clul2s3f70008yf3x7mada0gb", "clur52dfl0001vc3xlbdy1d7p",
	}, vaultIDs) {
		return
	}
	if !assert.Empty(t, address) {
		return
	}
	if !assert.Nil(t, ecSK) || !assert.Nil(t, edSK) {
		return
	}
}

func TestTool_Legacy_V1_ILM_Export_m0k(t *testing.T) {
	// use the correct file path for tests
	vaultID := "clujhtm9d0013wc3xso1b2m0k"

	files := []VaultsDataFile{
		{File: "./test-files/i.json", Mnemonics: mmI},
		{File: "./test-files/m.json", Mnemonics: mmM},
		{File: "./test-files/l.json", Mnemonics: mmL},
	}

	address, ecSK, edSK, vaultsFormData, err := runTool(files, &vaultID, nil, nil, nil, nil)

	if !assert.NoError(t, err) {
		return
	}
	if !assert.Len(t, vaultsFormData, 1) {
		return
	}
	if !assert.Equal(t, vaultID, vaultsFormData[0].VaultID) {
		return
	}
	if !assert.Equal(t, "0x66ee83f83002b01459b750233f7b21744e679182", address) {
		return
	}
	if !assert.Equal(t, "7d3c016f339f8cc797ee35502a5c93416d47bdd04360d22ea4fcaf85cec229b3",
		hex.EncodeToString(ecSK.Bytes())) {
		return
	}
	// no EdDSA key for this vault
	if !assert.Nil(t, edSK) {
		return
	}
}

func vaultIdsFromFormData(vaultFormData []VaultPickerItem) []string {
	vaultIDs := make([]string, len(vaultFormData))
	for i, v := range vaultFormData {
		vaultIDs[i] = v.VaultID
	}
	return vaultIDs
}
