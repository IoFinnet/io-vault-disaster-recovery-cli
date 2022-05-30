package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"math/big"
	"os"
	"strings"

	"github.com/binance-chain/tss-lib/crypto/vss"
	"github.com/binance-chain/tss-lib/ecdsa/keygen"
	. "github.com/decred/dcrd/dcrec/secp256k1"
	secp256k13 "github.com/decred/dcrd/dcrec/secp256k1/v2"
	errors2 "github.com/pkg/errors"
	"github.com/tyler-smith/go-bip39"
	"golang.org/x/crypto/sha3"
)

const (
	WORDS = 24
)

type (
	Vault struct {
		Name   string        `json:"name"`
		Curves []interface{} `json:"curves"`
	}

	SavedData struct {
		S map[string][]string
		V map[string]Vault
	}
)

func main() {
	reader := bufio.NewReader(os.Stdin)

	vaultID := flag.String("vault-id", "", "OPTIONAL: the vault id to export a keystore for")
	export := flag.String("export", "", "OPTIONAL: path to export keyfile")
	password := flag.String("password", "", "OPTIONAL: encryption password for keyfile")

	flag.Parse()
	files := flag.Args()
	if len(files) < 1 {
		fmt.Println("Please supply some input files on the command line.")
		flag.Usage()
		return
	}
	if *vaultID == "" {
		// flag.Usage()
		fmt.Println("No --vault-id was specified, so the tool will just list out the vault IDs available.")
		fmt.Println()
	}

	var vaultIdsToNamesMap map[string]Vault
	vaultShareData := make(map[string][]string)
	vaultShares := make([]*keygen.LocalPartySaveData, 0, len(files))

	fmt.Println("Preparing to decrypt the files. Please enter the secret words.")
	for i, file := range files {
		fmt.Printf("input %d secret words for file %d \"%s\": ", WORDS, i, file)
		phrase, _ := reader.ReadString('\n')
		phrase = strings.Replace(phrase, "\n", "", -1)
		phrase = strings.Replace(phrase, "\r", "", -1)
		words := strings.SplitN(phrase, " ", WORDS)
		if len(words) < WORDS {
			panic(fmt.Errorf("wanted %d phrase words but got %d", WORDS, len(words)))
		}

		// read file
		if _, err := os.Stat(file); err != nil {
			panic(err)
		}
		content, err := ioutil.ReadFile(file)
		if err != nil {
			panic(fmt.Errorf("file to read from file(%s): %w", file, err))
		}
		// ${deviceIdsStr};${twentyFourWords[0].word};${nonceHex};${tagHex};${ciphertext}
		// example: cl347srm8036882voar2o3yyy;minimum;04bb40eb0b322e19b65d68f7;749e68c3f00e5412126b3b7b193fe48d;...
		items := strings.SplitN(string(content), ";", 5)
		_, firstWord, aesNonceHex, aesTagHex, aesCTB64 := items[0], items[1], items[2], items[3], items[4]
		if words[0] != firstWord {
			panic(fmt.Errorf("wanted first word to be \"%s\" but got \"%s\"", firstWord, words[0]))
		}

		// decode aes bits
		aesKey32, err := bip39.EntropyFromMnemonic(phrase)
		if err != nil {
			panic(err)
		}
		// fmt.Printf("AES key size is %d\n", len(aesKey32))
		aesNonce, err := hex.DecodeString(aesNonceHex)
		if err != nil {
			panic(err)
		}
		aesTag, err := hex.DecodeString(aesTagHex)
		if err != nil {
			panic(err)
		}
		aesCT, err := base64.StdEncoding.DecodeString(aesCTB64)
		if err != nil {
			panic(err)
		}

		// decode ciphertext
		aesBlk, err := aes.NewCipher(aesKey32[:])
		if err != nil {
			panic(err)
		}
		aesGCM, err := cipher.NewGCM(aesBlk)
		if err != nil {
			panic(err)
		}
		// fmt.Printf("AES block size is %d\n", aesGCM.BlockSize())
		// if len(aesCT)%aesBlk.BlockSize() != 0 {
		// 	panic("ciphertext is not a multiple of the block size")
		// }

		// append the tag to the ciphertext, which is what golang's GCM implementation expects
		aesCT = append(aesCT, aesTag...)
		if aesCT, err = aesGCM.Open(nil, aesNonce, aesCT, nil); err != nil {
			panic(err)
		}

		aesCTStr := string(aesCT)
		if aesCTStr[0] != '{' {
			panic(fmt.Errorf("unable to parse json in file, first char is %s", aesCTStr[:1]))
		}
		// if aesCT, err = pkcs7Unpad(aesCT, aesBlk.BlockSize()); err != nil {
		// 	panic(err)
		// }

		// encrypted data format: [map(shares), map(vault ids to names)]
		// split := strings.SplitN(aesCTStr, "},{", 2)
		// firstPart := fmt.Sprintf("%s}", split[0][1:])
		// secondPart := fmt.Sprintf("{%s", split[1][:len(split[1])-1])
		data := new(SavedData)
		if err = json.Unmarshal(aesCT, data); err != nil {
			panic(errors2.Wrapf(err, "invalid data format - is this an old backup file? (code: 0)"))
		}
		jsonSharesMap := data.S
		vaultIdsToNamesMap = data.V
		fmt.Printf("%+v\n", vaultIdsToNamesMap)
		// if err = json.Unmarshal([]byte(firstPart), &jsonSharesMap); err != nil {
		// 	panic(err)
		// }
		// if err = json.Unmarshal([]byte(secondPart), &vaultIdsToNamesMap); err != nil {
		// 	panic(err)
		// }

		// [itemServer, itemUserId, deviceId, vaultId] = keyChainService.split(SEPARATOR)
		// example: dev.aq.systems–—–954f74ec-2d3c-4073-9af7-03b27fd31ff5–—–cl347srm8036882voar2o3yyy–—–cl347wz8w00006sx3f1g23p4s–—–privateShare
		for key, shares := range jsonSharesMap {
			if !strings.HasSuffix(key, "privateShare") {
				continue
			}
			split := strings.SplitN(key, "–—–", 5)
			vID := split[3]
			if _, ok := vaultShareData[vID]; !ok {
				vaultShareData[vID] = make([]string, 0, len(shares))
			}
			vaultShareData[vID] = append(vaultShareData[vID], shares...)
		}
	}

	if *vaultID == "" {
		fmt.Println("\nDecryption success.\nListing available vault IDs:")
		for vID := range vaultShareData {
			suffixStr := ""
			if vName, ok := vaultIdsToNamesMap[vID]; ok {
				suffixStr = fmt.Sprintf(" (\"%s\")", vName.Name)
			}
			fmt.Printf(" - %s%s\n", vID, suffixStr)
		}
		fmt.Println("\nRestart the tool and provide --vault-id to extract a vault's key.")
		fmt.Println("Example: recovery-tool.exe --vault-id cl347wz8w00006sx3f1g23p4s file.dat")
		return
	}
	if _, ok := vaultShareData[*vaultID]; !ok {
		panic(fmt.Errorf("provided files do not contain data for vault %s", *vaultID))
	}

	var t, tPlus1 int
	for _, sz := range vaultShareData[*vaultID] {
		shareData := new(keygen.LocalPartySaveData)
		if err := json.Unmarshal([]byte(sz), &shareData); err != nil {
			panic(errors2.Wrapf(err, "invalid data format - is this an old backup file? (code: 2)"))
		}
		vaultShares = append(vaultShares, shareData)
		tPlus1++
	}
	t = tPlus1 - 1

	vssShares := make(vss.Shares, len(vaultShares))
	for i, el := range vaultShares {
		share := vss.Share{
			Threshold: t,
			ID:        el.ShareID,
			Share:     el.Xi,
		}
		vssShares[i] = &share
	}

	// TODO: select the curve
	tssPrivateKey, err := vssShares[:tPlus1].ReConstruct(S256())
	if err != nil {
		fmt.Printf("error in tss verify")
	}

	privKey := NewPrivateKey(tssPrivateKey)
	pk := privKey.PubKey()

	// TODO: encode Ethereum address
	_, address, err := getTSSPubKey(pk.X, pk.Y)
	if err != nil {
		panic(err)
	}
	fmt.Printf("recovered ETH address: %s\n", address)
	fmt.Printf("recovered SK: %v\n", hex.EncodeToString(tssPrivateKey.Bytes()))

	if len(*export) > 0 && len(*password) > 0 {
		keyfile, err := exportKeyStore(privKey.Serialize(), *password)
		if err != nil {
			panic(err)
		}

		jsonString, _ := json.Marshal(keyfile)
		err = ioutil.WriteFile(*export, jsonString, os.ModePerm)
		if err != nil {
			panic(err)
		}
		fmt.Printf("wrote keystore to: %+v\n", *export)
	} else {
		fmt.Printf("not exporting a keystore due to missing CLI flags!\n")
	}
}

func getTSSPubKey(x, y *big.Int) (*secp256k13.PublicKey, string, error) {
	if x == nil || y == nil {
		return nil, "", errors.New("invalid public key coordinates")
	}
	pubKey := NewPublicKey(x, y)
	var pubKeyBz [65]byte
	copy(pubKeyBz[:], pubKey.SerializeUncompressed())
	fmt.Printf("pk: %s\n", hex.EncodeToString(pubKeyBz[:]))

	hash := sha3.NewLegacyKeccak256()
	hash.Write(pubKeyBz[1:])
	sum := hash.Sum(nil)
	addr := fmt.Sprintf("0x%s", hex.EncodeToString(sum[len(sum)-20:]))

	return pubKey, addr, nil
}
