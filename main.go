package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"math/big"
	"os"
	"strings"

	"github.com/binance-chain/tss-lib/crypto/vss"
	"github.com/binance-chain/tss-lib/ecdsa/keygen"
	secp256k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
	errors2 "github.com/pkg/errors"
	"github.com/tyler-smith/go-bip39"
	"golang.org/x/crypto/sha3"
)

const (
	WORDS = 24
)

type (
	SavedData struct {
		Vaults map[string]CipheredVaultMap `json:"vaults"`
	}

	CipheredVaultMap map[int]CipheredVault

	CipheredVault struct {
		CipherTextB64 string       `json:"ciphertext"`
		CipherParams  CipherParams `json:"cipherparams"`
		Cipher        string       `json:"cipher"`
		Hash          string       `json:"hash"`
	}
	CipherParams struct {
		IV  string `json:"iv"`
		Tag string `json:"tag"`
	}

	ClearVaultMap map[string]*ClearVault
	ClearVault    struct {
		Name             string   `json:"name"`
		Quroum           int      `json:"threshold"`
		Shares           []string `json:"shares"`
		LastReShareNonce int      `json:"-"`
	}

	VaultAllShares map[string][]*keygen.LocalPartySaveData
)

func main() {
	reader := bufio.NewReader(os.Stdin)

	vaultID := flag.String("vault-id", "", "(Optional) The vault id to export the keys for.")
	nonceOverride := flag.Int("nonce", -1, "(Optional) Reshare Nonce override. Try it if the tool advises you to do so.")
	quorumOverride := flag.Int("threshold", 0, "(Optional) Vault Quorum (Threshold) override. Try it if the tool advises you to do so.")
	exportKSFile := flag.String("export", "", "(Optional) Path to export Ethereum wallet keystore file.")
	passwordForKS := flag.String("password", "", "(Optional) Encryption password for the Ethereum wallet keystore; use with --export")

	flag.Parse()
	files := flag.Args()
	if len(files) < 1 {
		fmt.Println("Please supply some input files on the command line. \nExample: recovery-tool.exe [-flags] file1.json file2.json ... \n\nOptional flags:")
		flag.PrintDefaults()
		return
	}
	if *vaultID == "" {
		// flag.Usage()
		fmt.Println("No --vault-id was specified, so the tool will just list out the available vault IDs.")
	}

	println()
	fmt.Println("*** io.finnet Key Recovery Tool ***")

	if *nonceOverride > -1 {
		fmt.Printf("\n⚠ Using reshare nonce override: %d. Be sure to set the threshold of the vault at this reshare point with --threshold, or recovery will produce incorrect data.\n", *nonceOverride)
	}
	if *quorumOverride > 0 {
		fmt.Printf("\n⚠ Using vault quorum override: %d.\n", *quorumOverride)
	}
	if *nonceOverride > -1 || *quorumOverride > 0 {
		println()
	}

	// Internal data structures
	clearVaults := make(ClearVaultMap, len(files)*16)
	vaultAllShares := make(VaultAllShares, len(files)*16) // headroom
	vaultLastNonces := make(map[string]int, len(files)*16)

	// Make sure all files exist, and ensure they're unique
	{
		uniqueFiles := make(map[string]struct{})
		for _, file := range files {
			// read file and basic validate
			if _, err := os.Stat(file); err != nil {
				panic(errors2.Errorf("⚠ unable to see file `%s` - does it exist?: %s", file, err))
			}
			if _, ok := uniqueFiles[file]; ok {
				panic(errors2.Errorf("⚠ duplicate file `%s`", file))
			}
			uniqueFiles[file] = struct{}{}
		}
	}

	// Do the main routine
	fmt.Println("Preparing to decrypt the files. Please enter the secret words.")
	for i, file := range files {
		// read file and basic validate
		if _, err := os.Stat(file); err != nil {
			panic(errors2.Errorf("⚠ unable to see file `%s` - does it exist?: %s", file, err))
		}
		content, err := os.ReadFile(file)
		if err != nil {
			panic(fmt.Errorf("⚠ file to read from file(%s): %s", file, err))
		}
		if len(content) == 0 || content[0] != '{' {
			panic(fmt.Errorf("⚠ invalid file format, expecting json. first char is %s", content[:1]))
		}

		saveData := new(SavedData)
		if err = json.Unmarshal(content, saveData); err != nil {
			panic(errors2.Wrapf(err, "⚠ invalid saveData format - is this an old backup file? (code: 1)"))
		}

		// user inputs the secret words
		fmt.Printf("\n➤ Now input %d secret words for file %d \"%s\":\n", WORDS, i+1, file)
		phrase, _ := reader.ReadString('\n')
		phrase = strings.Replace(phrase, "\n", "", -1)
		phrase = strings.Replace(phrase, "\r", "", -1)
		words := strings.SplitN(phrase, " ", WORDS)
		if len(words) < WORDS {
			panic(fmt.Errorf("⚠ wanted %d phrase words but got %d", WORDS, len(words)))
		}

		// words -> key
		aesKey32, err := bip39.EntropyFromMnemonic(phrase)
		if err != nil {
			panic(fmt.Errorf("⚠ failed to generate key from mnemonic, are your words correct? %s", err))
		}

		// decrypt the vaults into clear vaults
		for vID, resharesMap := range saveData.Vaults {
			// only look at the vault we're interested in, if one was supplied
			if *vaultID != "" && vID != *vaultID {
				continue
			}

			// take the highest reshareNonce we have saved (best effort)
			lastReshareNonce := -1
			for nonce := range resharesMap {
				// support the --nonce flag to override the last reshare nonce we use
				if *vaultID != "" && *nonceOverride > -1 && *nonceOverride != nonce {
					continue
				}
				if nonce > lastReshareNonce {
					lastReshareNonce = nonce
				}
			}
			if lastReshareNonce == -1 {
				//panic(fmt.Errorf("⚠ no share data found for vault `%s` in save file", vID))
				continue // not a show stopper
			}
			if glbLastReShareNonce, ok := vaultLastNonces[vID]; ok && glbLastReShareNonce != lastReshareNonce {
				fmt.Printf("\n⚠ Non matching reshare nonce for vault `%s`. You may have to specify prior reshare config with --nonce and --threshold when recovering that vault.\n", vID)
				if lastReshareNonce-1 >= 0 {
					fmt.Printf("⚠ If you have problems recovering that vault, you could try: --vault-id %s --nonce %d --threshold x. Replace x with previous vault threshold.\n", vID, lastReshareNonce-1)
				} else {
					println()
				}
			}
			vaultLastNonces[vID] = lastReshareNonce
			cipheredVault := resharesMap[lastReshareNonce]

			// DECRYPT
			aesNonce, err := hex.DecodeString(cipheredVault.CipherParams.IV)
			if err != nil {
				panic(errors2.Errorf("⚠ failed to decrypt vault %s: %s (on nonce decode)", vID, err))
			}
			aesTag, err := hex.DecodeString(cipheredVault.CipherParams.Tag)
			if err != nil {
				panic(errors2.Errorf("⚠ failed to decrypt vault %s: %s (on tag decode)", vID, err))
			}
			aesCT, err := base64.StdEncoding.DecodeString(cipheredVault.CipherTextB64)
			if err != nil {
				panic(errors2.Errorf("⚠ failed to decrypt vault %s: %s (on ciphertext decode)", vID, err))
			}

			// init AES-GCM cipher
			aesBlk, err := aes.NewCipher(aesKey32[:])
			if err != nil {
				panic(errors2.Errorf("⚠ failed to decrypt vault %s: %s (on cipher init 1)", vID, err))
			}
			aesGCM, err := cipher.NewGCM(aesBlk)
			if err != nil {
				panic(errors2.Errorf("⚠ failed to decrypt vault %s: %s (on cipher init 2)", vID, err))
			}

			// append the tag to the ciphertext, which is what golang's GCM implementation expects
			aesCT = append(aesCT, aesTag...)
			plainload, err := aesGCM.Open(nil, aesNonce, aesCT, nil)
			if err != nil {
				panic(errors2.Errorf("⚠ failed to decrypt vault %s: %s (on decrypt)", vID, err))
			}
			expHash := sha512.Sum512(plainload)
			if hex.EncodeToString(expHash[:]) != cipheredVault.Hash {
				panic(errors2.Errorf("⚠ failed to decrypt vault %s: %s (hash mismatch)", vID, err))
			}

			// decode from json
			clearVaults[vID] = new(ClearVault)
			if err = json.Unmarshal(plainload, clearVaults[vID]); err != nil {
				panic(errors2.Wrapf(err, "invalid saveData format - is this an old backup file? (code: 3)"))
			}
			clearVaults[vID].LastReShareNonce = lastReshareNonce

			// rack up the shares
			if _, ok := vaultAllShares[vID]; !ok {
				vaultAllShares[vID] = make([]*keygen.LocalPartySaveData, 0, len(clearVaults[vID].Shares))
			}
			shareDatas := make([]*keygen.LocalPartySaveData, len(clearVaults[vID].Shares))
			for i, strShare := range clearVaults[vID].Shares {
				shareData := new(keygen.LocalPartySaveData)
				if err = json.Unmarshal([]byte(strShare), shareData); err != nil {
					panic(errors2.Wrapf(err, "invalid data format - is this an old backup file? (code: 4)"))
				}
				shareDatas[i] = shareData
			}
			vaultAllShares[vID] = append(vaultAllShares[vID], shareDatas...)
		}
	}

	// Just list the ID's and names?
	if *vaultID == "" {
		fmt.Println("\nDecryption success.\nListing available vault IDs and other known data:")
		for vID, vault := range clearVaults {
			suffixStr := fmt.Sprintf("  \"%s\"  (shares: %d, need: %d, nonce: %d)",
				vault.Name, len(vaultAllShares[vID]), vault.Quroum, vault.LastReShareNonce)
			fmt.Printf(" - %s%s\n", vID, suffixStr)
		}
		fmt.Println("\nNow you must restart the tool and provide the --vault-id flag to extract a vault's key.")
		fmt.Println("This is only possible if `shares` >= `need` for that vault in the list above. If it's not, you must collect more shares.")
		fmt.Println("\nExample: recovery-tool.exe --vault-id cl347wz8w00006sx3f1g23p4s file.json")
		return
	}

	println()
	if _, ok := vaultAllShares[*vaultID]; !ok {
		panic(fmt.Errorf("⚠ provided files do not contain data for vault `%s` with the expected reshare nonce", *vaultID))
	}

	tPlus1 := clearVaults[*vaultID].Quroum
	if *quorumOverride > 0 {
		tPlus1 = *quorumOverride
	}
	vssShares := make(vss.Shares, len(vaultAllShares[*vaultID]))
	if len(vaultAllShares[*vaultID]) < tPlus1 {
		panic(fmt.Errorf("⚠ not enough shares to recover the key for vault %s (need %d, have %d)", *vaultID, tPlus1, len(vaultAllShares[*vaultID])))
	}
	var share0ECDSAPubKey *ecdsa.PublicKey
	for i, el := range vaultAllShares[*vaultID] {
		vssShares[i] = &vss.Share{
			Threshold: tPlus1 - 1,
			ID:        el.ShareID,
			Share:     el.Xi,
		}
		if i == 0 {
			share0ECDSAPubKey = el.ECDSAPub.ToBtcecPubKey().ToECDSA()
		}
	}

	// TODO: select the curve
	tssPrivateKey, err := vssShares.ReConstruct(secp256k1.S256())
	if err != nil {
		fmt.Printf("error in tss verify")
	}

	scl := secp256k1.ModNScalar{}
	scl.SetByteSlice(tssPrivateKey.Bytes())
	privKey := secp256k1.NewPrivateKey(&scl)
	pk := privKey.PubKey()

	// ensure the pk matches our expected share 0 pk
	if !pk.ToECDSA().Equal(share0ECDSAPubKey) {
		panic(fmt.Errorf("⚠ recovered public key did not match the expected share 0 public key! did you input the right threshold?"))
	}

	// encode Ethereum address
	_, address, err := getTSSPubKey(pk.X(), pk.Y())
	if err != nil {
		panic(err)
	}
	fmt.Println("*** Success! ***")
	fmt.Printf("Recovered ETH address: %s\n", address)
	fmt.Printf("Recovered private key (for ETH/MetaMask): %s\n", hex.EncodeToString(tssPrivateKey.Bytes()))
	fmt.Printf("Recovered testnet WIF (for BTC/Electrum): %s\n", toBitcoinWIF(tssPrivateKey.Bytes(), true, true))
	fmt.Printf("Recovered mainnet WIF (for BTC/Electrum): %s\n", toBitcoinWIF(tssPrivateKey.Bytes(), false, true))

	if len(*exportKSFile) > 0 {
		if len(*passwordForKS) == 0 {
			fmt.Println("⚠ --password flag is required to export keystore file")
			return
		}
		keyfile, err := exportKeyStore(privKey.Serialize(), *passwordForKS)
		if err != nil {
			panic(err)
		}

		jsonString, _ := json.Marshal(keyfile)
		err = os.WriteFile(*exportKSFile, jsonString, os.ModePerm)
		if err != nil {
			panic(err)
		}
		fmt.Printf("\nWrote keystore to: %s.\n", *exportKSFile)
	}
}

func getTSSPubKey(x, y *big.Int) (*secp256k1.PublicKey, string, error) {
	if x == nil || y == nil {
		return nil, "", errors.New("invalid public key coordinates")
	}
	pubKey, err := secp256k1.ParsePubKey(append([]byte{0x04}, append(x.Bytes(), y.Bytes()...)...))
	if err != nil {
		return nil, "", err
	}
	var pubKeyBz [65]byte
	copy(pubKeyBz[:], pubKey.SerializeUncompressed())

	hash := sha3.NewLegacyKeccak256()
	hash.Write(pubKeyBz[1:])
	sum := hash.Sum(nil)
	addr := fmt.Sprintf("0x%s", hex.EncodeToString(sum[len(sum)-20:]))

	return pubKey, addr, nil
}
