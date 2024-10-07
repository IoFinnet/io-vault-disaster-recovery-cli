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
	"sort"
	"strings"

	"github.com/binance-chain/tss-lib/crypto/vss"
	"github.com/binance-chain/tss-lib/ecdsa/keygen"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/ethereum/go-ethereum/accounts/keystore"
	"github.com/ethereum/go-ethereum/common"
	"github.com/google/uuid"
	errors2 "github.com/pkg/errors"
	"github.com/tyler-smith/go-bip39"
	"golang.org/x/crypto/sha3"
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

	ClearVaultMap   map[string]*ClearVault
	ClearVaultCurve struct {
		Algorithm string   `json:"algorithm"`
		Shares    []string `json:"shares"`
	}
	ClearVault struct {
		Name             string            `json:"name"`
		Quroum           int               `json:"threshold"`
		SharesLegacy     []string          `json:"shares"`
		LastReShareNonce int               `json:"-"`
		Curves           []ClearVaultCurve `json:"curves"`
	}

	VaultAllShares map[string][]*keygen.LocalPartySaveData
)

const (
	WORDS         = 24
	v2MagicPrefix = "_V2_"
)

var (
	// ANSI escape seqs for colours in the terminal
	ansiCodes = map[string]string{
		"bold":        "\033[1m",
		"invertOn":    "\033[7m",
		"darkRedBG":   "\033[41m",
		"darkGreenBG": "\033[42m",
		"reset":       "\033[0m",
	}
)

func main() {
	vaultID := flag.String("vault-id", "", "(Optional) The vault id to export the keys for.")
	nonceOverride := flag.Int("nonce", -1, "(Optional) Reshare Nonce override. Try it if the tool advises you to do so.")
	quorumOverride := flag.Int("threshold", 0, "(Optional) Vault Quorum (Threshold) override. Try it if the tool advises you to do so.")
	exportKSFile := flag.String("export", "wallet.json", "(Optional) Filename to export a Ethereum/MetaMask wallet v3 JSON file to.")
	passwordForKS := flag.String("password", "", "(Optional) Encryption password for the Ethereum wallet v3 file; use with -export")

	flag.Parse()
	files := flag.Args()
	if len(files) < 1 {
		fmt.Println("Please supply some input files on the command line. \nExample: recovery-tool.exe [-flags] file1.json file2.json ... \n\nOptional flags:")
		flag.PrintDefaults()
		return
	}

	println()
	fmt.Printf("%s%s                                     %s\n", ansiCodes["invertOn"], ansiCodes["bold"], ansiCodes["reset"])
	fmt.Printf("%s%s     io.finnet Key Recovery Tool     %s\n", ansiCodes["invertOn"], ansiCodes["bold"], ansiCodes["reset"])
	fmt.Printf("%s%s               v3.1.1                %s\n", ansiCodes["invertOn"], ansiCodes["bold"], ansiCodes["reset"])
	fmt.Printf("%s%s                                     %s\n", ansiCodes["invertOn"], ansiCodes["bold"], ansiCodes["reset"])
	println()

	address, sk, _, err := runTool(files, vaultID, nonceOverride, quorumOverride, exportKSFile, passwordForKS)
	if err != nil {
		println()
		fmt.Printf("%s%s         %s\n", ansiCodes["darkRedBG"], ansiCodes["bold"], ansiCodes["reset"])
		fmt.Printf("%s%s  Error  %s  %s.\n", ansiCodes["darkRedBG"], ansiCodes["bold"], ansiCodes["reset"], err)
		fmt.Printf("%s%s         %s\n", ansiCodes["darkRedBG"], ansiCodes["bold"], ansiCodes["reset"])
		println()
		os.Exit(1)
		return
	}
	defer sk.SetInt64(0)
	if sk == nil {
		// only listing vaults
		os.Exit(0)
		return
	}

	fmt.Printf("%s%s                %s\n", ansiCodes["darkGreenBG"], ansiCodes["bold"], ansiCodes["reset"])
	fmt.Printf("%s%s    Success!    %s\n", ansiCodes["darkGreenBG"], ansiCodes["bold"], ansiCodes["reset"])
	fmt.Printf("%s%s                %s\n", ansiCodes["darkGreenBG"], ansiCodes["bold"], ansiCodes["reset"])

	fmt.Printf("\nYour vault has been recovered. Make sure the following address matches your vault's Ethereum address:\n")
	fmt.Printf("%s%s%s\n", ansiCodes["bold"], address, ansiCodes["reset"])

	fmt.Printf("\nHere is your private key for Ethereum and Tron assets. Keep safe and do not share with anyone.\n")
	fmt.Printf("Recovered private key (for ETH/MetaMask, TronLink): %s%s%s\n", ansiCodes["bold"], hex.EncodeToString(sk.Bytes()), ansiCodes["reset"])

	fmt.Printf("\nHere are your private keys for Bitcoin assets. Keep safe and do not share with anyone.\n")
	fmt.Printf("Recovered testnet WIF (for Electrum Wallet): %s%s%s\n", ansiCodes["bold"], toBitcoinWIF(sk.Bytes(), true, true), ansiCodes["reset"])
	fmt.Printf("Recovered mainnet WIF (for Electrum Wallet): %s%s%s\n", ansiCodes["bold"], toBitcoinWIF(sk.Bytes(), false, true), ansiCodes["reset"])
}

func runTool(files []string, vaultID *string, nonceOverride *int, quorumOverride *int, exportKSFile *string, passwordForKS *string, mnemonics ...string) (address string, sk *big.Int, vaultIDs []string, welp error) {
	reader := bufio.NewReader(os.Stdin)

	if nonceOverride != nil && *nonceOverride > -1 {
		fmt.Printf("\n⚠ Using reshare nonce override: %d. Be sure to set the threshold of the vault at this reshare point with -threshold, or recovery will produce incorrect data.\n", *nonceOverride)
	}
	if quorumOverride != nil && *quorumOverride > 0 {
		fmt.Printf("\n⚠ Using vault quorum override: %d.\n", *quorumOverride)
	}
	if (nonceOverride != nil && *nonceOverride > -1) || (quorumOverride != nil && *quorumOverride > 0) {
		println()
	}

	justListingVaults := vaultID == nil || *vaultID == ""
	if justListingVaults {
		fmt.Printf("NOTE: No -vault-id was specified. The tool will just list out the available vault IDs.\n")
	}

	// Internal & returned data structures
	clearVaults := make(ClearVaultMap, len(files)*16)
	vaultAllShares := make(VaultAllShares, len(files)*16) // headroom
	vaultLastNonces := make(map[string]int, len(files)*16)

	// Make sure all files exist, and ensure they're unique
	{
		uniqueFiles := make(map[string]struct{})
		for _, file := range files {
			// read file and basic validate
			if _, err := os.Stat(file); err != nil {
				welp = errors2.Errorf("⚠ unable to see file `%s` - does it exist?: %s", file, err)
				return
			}
			if _, ok := uniqueFiles[file]; ok {
				welp = errors2.Errorf("⚠ duplicate file `%s`", file)
				return
			}
			uniqueFiles[file] = struct{}{}
		}
	}

	// Do the main routine
	fmt.Println("Preparing to decrypt the files. Please enter the secret words.")
	for i, file := range files {
		// read file and basic validate
		if _, err := os.Stat(file); err != nil {
			welp = errors2.Errorf("⚠ unable to see file `%s` - does it exist?: %s", file, err)
			return
		}
		content, err := os.ReadFile(file)
		if err != nil {
			welp = fmt.Errorf("⚠ file to read from file(%s): %s", file, err)
			return
		}
		if len(content) == 0 || content[0] != '{' {
			welp = fmt.Errorf("⚠ invalid file format, expecting json. first char is %s", content[:1])
			return
		}

		saveData := new(SavedData)
		if err = json.Unmarshal(content, saveData); err != nil {
			welp = errors2.Wrapf(err, "⚠ invalid saveData format - is this an old backup file? (code: 1)")
			return
		}

		phrase := ""
		if len(mnemonics) < len(files) {
			// user inputs the secret phrase
			fmt.Printf("\nNow input %d secret words for file %d \"%s\":\n➤ ", WORDS, i+1, file)
			phrase, _ = reader.ReadString('\n')
			phrase = strings.Replace(phrase, "\n", "", -1)
			phrase = strings.Replace(phrase, "\r", "", -1)
			words := strings.SplitN(phrase, " ", WORDS)
			if len(words) < WORDS {
				welp = fmt.Errorf("⚠ wanted %d phrase words but got %d", WORDS, len(words))
				return
			}
		} else {
			// we have the secret phrase passed in through an arg
			phrase = mnemonics[i]
		}

		// phrase -> key
		aesKey32, err := bip39.EntropyFromMnemonic(phrase)
		if err != nil {
			welp = fmt.Errorf("⚠ failed to generate key from mnemonic, are your words correct? %s", err)
			return
		}

		// decrypt the vaults into clear vaults
		for vID, resharesMap := range saveData.Vaults {
			// only look at the vault we're interested in, if one was supplied
			if !justListingVaults && vID != *vaultID {
				continue
			}

			// take the highest reshareNonce we have saved (best effort)
			lastReshareNonce := -1
			for nonce := range resharesMap {
				// support the -nonce flag to override the last reshare nonce we use
				if !justListingVaults && nonceOverride != nil && *nonceOverride > -1 && *nonceOverride != nonce {
					continue
				}
				if nonce > lastReshareNonce {
					lastReshareNonce = nonce
				}
			}
			if lastReshareNonce == -1 {
				//welp = fmt.Errorf("⚠ no share data found for vault `%s` in save file", vID)
				continue // not a show stopper
			}
			if glbLastReShareNonce, ok := vaultLastNonces[vID]; ok && glbLastReShareNonce != lastReshareNonce {
				fmt.Printf("\n⚠ Non matching reshare nonce for vault `%s`. You may have to specify prior reshare config with -nonce and -threshold when recovering that vault.\n", vID)
				if lastReshareNonce-1 >= 0 {
					fmt.Printf("⚠ If you have problems recovering that vault, you could try: -vault-id %s -nonce %d -threshold x. Replace x with previous vault threshold.\n", vID, lastReshareNonce-1)
				} else {
					println()
				}
			}
			vaultLastNonces[vID] = lastReshareNonce
			cipheredVault := resharesMap[lastReshareNonce]

			// DECRYPT
			aesNonce, err := hex.DecodeString(cipheredVault.CipherParams.IV)
			if err != nil {
				welp = errors2.Errorf("⚠ failed to decrypt vault %s: %s (on nonce decode)", vID, err)
				return
			}
			aesTag, err := hex.DecodeString(cipheredVault.CipherParams.Tag)
			if err != nil {
				welp = errors2.Errorf("⚠ failed to decrypt vault %s: %s (on tag decode)", vID, err)
				return
			}
			aesCT, err := base64.StdEncoding.DecodeString(cipheredVault.CipherTextB64)
			if err != nil {
				welp = errors2.Errorf("⚠ failed to decrypt vault %s: %s (on ciphertext decode)", vID, err)
				return
			}

			// init AES-GCM cipher
			aesBlk, err := aes.NewCipher(aesKey32)
			if err != nil {
				welp = errors2.Errorf("⚠ failed to decrypt vault %s: %s (on cipher init 1)", vID, err)
				return
			}
			aesGCM, err := cipher.NewGCM(aesBlk)
			if err != nil {
				welp = errors2.Errorf("⚠ failed to decrypt vault %s: %s (on cipher init 2)", vID, err)
				return
			}

			// append the tag to the ciphertext, which is what golang's GCM implementation expects
			aesCT = append(aesCT, aesTag...)
			plainload, err := aesGCM.Open(nil, aesNonce, aesCT, nil)
			if err != nil {
				welp = errors2.Errorf("⚠ failed to decrypt vault %s: %s (on decrypt)", vID, err)
				return
			}
			expHash := sha512.Sum512(plainload)
			if hex.EncodeToString(expHash[:]) != cipheredVault.Hash {
				welp = errors2.Errorf("⚠ failed to decrypt vault %s: %s (hash mismatch)", vID, err)
				return
			}

			// decode vault from json
			clearVaults[vID] = new(ClearVault)
			if err = json.Unmarshal(plainload, clearVaults[vID]); err != nil {
				welp = errors2.Wrapf(err, "invalid saveData format - is this an old backup file? (code: 3)")
				return
			}
			clearVaults[vID].LastReShareNonce = lastReshareNonce

			// rack up the shares
			sharesList := clearVaults[vID].SharesLegacy
			if sharesList == nil {
				for _, curve := range clearVaults[vID].Curves {
					if curve.Algorithm == "ECDSA" {
						sharesList = curve.Shares
						fmt.Printf("Processing new vault \"%s\" (%s).\n", clearVaults[vID].Name, vID)
						break
					}
				}
			} else {
				fmt.Printf("Processing legacy vault \"%s\" (%s).\n", clearVaults[vID].Name, vID)
			}
			if sharesList == nil {
				panic(fmt.Errorf("no legacy or new shares found for vault %s %s", vID, clearVaults[vID].Name))
			}
			if _, ok := vaultAllShares[vID]; !ok {
				vaultAllShares[vID] = make([]*keygen.LocalPartySaveData, 0, len(sharesList))
			}
			shareDatas := make([]*keygen.LocalPartySaveData, len(sharesList))
			for j, strShare := range sharesList {
				// handle compressed "V2" format (ECDSA)
				hadPrefix := strings.HasPrefix(strShare, v2MagicPrefix)
				if hadPrefix {
					strShare = strings.TrimPrefix(strShare, v2MagicPrefix)
					expShareID, b64Part, found := strings.Cut(strShare, "_")
					if !found {
						welp = errors.New("failed to split on share ID delim in V2 save data")
						return
					}
					deflated, err2 := base64.StdEncoding.DecodeString(b64Part)
					if err2 != nil {
						welp = errors2.Wrapf(err, "failed to decode base64 part of V2 save data")
						return
					}
					inflated, err2 := inflateSaveDataJSON(deflated)
					// shareID integrity check
					abridgedData := new(struct {
						ShareID *big.Int `json:"shareID"`
					})
					if err2 = json.Unmarshal(inflated, abridgedData); err2 != nil {
						welp = errors2.Wrapf(err, "invalid data format - is this an old backup file? (code: 4)")
						return
					}
					if abridgedData.ShareID.String() != expShareID {
						welp = fmt.Errorf("share ID mismatch in V2 save data with ShareID %s", abridgedData.ShareID)
						return
					}
					strShare = string(inflated)

					// log deflated vs inflated sizes in KB
					if !justListingVaults {
						fmt.Printf("Processing V2 share %s.\t %.1f KB → %.1f KB\n",
							abridgedData.ShareID, float64(len(deflated))/1024, float64(len(inflated))/1024)
					}
				}
				// proceed with regular json unmarshal
				shareData := new(keygen.LocalPartySaveData)
				if err = json.Unmarshal([]byte(strShare), shareData); err != nil {
					welp = errors2.Wrapf(err, "invalid data format - is this an old backup file? (code: 4)")
					return
				}
				// log out a variation of this line if the share is legacy
				if !hadPrefix && !justListingVaults {
					fmt.Printf("Processing V1 share %s.\t %.1f KB\n",
						shareData.ShareID, float64(len(strShare))/1024)
				}
				shareDatas[j] = shareData
			}
			vaultAllShares[vID] = append(vaultAllShares[vID], shareDatas...)
		}
		phrase = ""
		clear(aesKey32)
		if len(mnemonics) >= i+1 {
			mnemonics[i] = ""
		}
	}
	clear(mnemonics)

	// populate vault IDs
	vaultIDs = make([]string, 0, len(files)*16)
	for vID := range clearVaults {
		vaultIDs = append(vaultIDs, vID)
	}
	sort.Strings(vaultIDs)

	// Just list the ID's and names?
	if justListingVaults {
		fmt.Println("\n━━━━━━\nDecryption success.\nListing available vault IDs and other known data:")
		for _, vID := range vaultIDs {
			vault := clearVaults[vID]
			suffixStr := fmt.Sprintf("  \"%s\"  (shares: %d, need: %d, nonce: %d)",
				vault.Name, len(vaultAllShares[vID]), vault.Quroum, vault.LastReShareNonce)
			fmt.Printf("  - %s%s\n", vID, suffixStr)
		}
		fmt.Println("\n\n━━━━━━\nNow you must restart the tool and provide the -vault-id flag to extract a vault's key.")
		fmt.Println("This is only possible if `shares >= need` for that vault in the list above. If it's not, you must collect more shares.")
		fmt.Println("\nExample: recovery-tool.exe -vault-id cl347wz8w00006sx3f1g23p4s file.json")
		return "", nil, vaultIDs, nil
	}

	println()
	if _, ok := vaultAllShares[*vaultID]; !ok {
		welp = fmt.Errorf("⚠ provided files do not contain data for vault `%s` with the expected reshare nonce", *vaultID)
		return
	}

	tPlus1 := clearVaults[*vaultID].Quroum
	if quorumOverride != nil && *quorumOverride > 0 {
		tPlus1 = *quorumOverride
	}
	vssShares := make(vss.Shares, len(vaultAllShares[*vaultID]))
	if len(vaultAllShares[*vaultID]) < tPlus1 {
		welp = fmt.Errorf("⚠ not enough shares to recover the key for vault %s (need %d, have %d)", *vaultID, tPlus1, len(vaultAllShares[*vaultID]))
		return
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

	if sk, welp = vssShares.ReConstruct(secp256k1.S256()); welp != nil {
		return
	}

	scl := secp256k1.ModNScalar{}
	scl.SetByteSlice(sk.Bytes())
	privKey := secp256k1.NewPrivateKey(&scl)
	pk := privKey.PubKey()

	// ensure the pk matches our expected share 0 pk
	if !pk.ToECDSA().Equal(share0ECDSAPubKey) {
		welp = fmt.Errorf("⚠ recovered public key did not match the expected share 0 public key! did you input the right threshold?")
		return
	}

	// encode Ethereum address
	if _, address, welp = getTSSPubKey(pk.X(), pk.Y()); welp != nil {
		return
	}

	// write out keystore file
	if exportKSFile != nil && len(*exportKSFile) > 0 {
		if passwordForKS != nil && len(*passwordForKS) == 0 {
			fmt.Printf("NOTE: -password flag is required to export wallet v3 file `%s`. A wallet v3 file will not be created this time.\n\n", *exportKSFile)
			return
		}
		ksUuid, err2 := uuid.NewRandom()
		if err2 != nil {
			welp = fmt.Errorf("⚠ could not create random uuid: %v", err2)
			return
		}
		key := &keystore.Key{
			Id:         ksUuid,
			Address:    common.HexToAddress(address),
			PrivateKey: privKey.ToECDSA(),
		}
		keyfile, err2 := keystore.EncryptKey(key, *passwordForKS, keystore.StandardScryptN, keystore.StandardScryptP)
		if err2 != nil {
			welp = fmt.Errorf("⚠ could not create the wallet v3 file json: %v", err2)
			return
		}

		if welp = os.WriteFile(*exportKSFile, keyfile, os.ModePerm); welp != nil {
			return
		}
		fmt.Printf("\nWrote a MetaMask wallet v3 file to: %s.\n", *exportKSFile)
	}
	return address, sk, vaultIDs, nil
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
