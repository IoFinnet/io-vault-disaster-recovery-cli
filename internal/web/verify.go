// Copyright (C) 2021 io finnet group, inc.
// SPDX-License-Identifier: AGPL-3.0-or-later
// Full license text available in LICENSE file in repository root.

package web

import (
	"bytes"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"path/filepath"
	"time"

	"github.com/IoFinnet/io-vault-disaster-recovery-cli/internal/fileutils"
	"github.com/IoFinnet/io-vault-disaster-recovery-cli/internal/hd"
	"github.com/IoFinnet/io-vault-disaster-recovery-cli/internal/recoverypipeline"
	"github.com/IoFinnet/io-vault-disaster-recovery-cli/internal/solana"
	"github.com/IoFinnet/io-vault-disaster-recovery-cli/internal/xrpl"
	"github.com/decred/dcrd/dcrec/edwards/v2"
)

// Source kinds only the web layer knows, so the pipeline never reports them.
const (
	// sourceKindLegacyZipEntry marks a JSON export the server extracted from a legacy ZIP archive.
	sourceKindLegacyZipEntry = "legacy-zip-entry"
	// sourceKindZipArchive marks an uploaded ZIP archive that could not be opened, so none of its
	// files were checked. It is always reported at the error level.
	sourceKindZipArchive = "zip-archive"
)

// VerifyResponse is the /api/verify response. It holds identifiers, public keys and addresses
// only, never key material.
type VerifyResponse struct {
	CheckedAt string               `json:"checkedAt"`
	Sources   []VerifySourceResult `json:"sources"`
	Vaults    []VerifyVaultResult  `json:"vaults"`
	Warnings  []string             `json:"warnings"`

	// HDAddresses is present only when the request carried an HD addresses CSV.
	HDAddresses *VerifyHDResult `json:"hdAddresses,omitempty"`
}

// VerifyHDResult reports the HD addresses CSV checked against the vaults' public keys. No private
// key is derived: child public keys come from each xpub alone.
type VerifyHDResult struct {
	File  string        `json:"file"`
	Error string        `json:"error,omitempty"` // the CSV could not be read; Rows is empty
	Rows  []VerifyHDRow `json:"rows"`
}

// VerifyHDRow is the check for one CSV row.
type VerifyHDRow struct {
	Row              int    `json:"row"` // line number in the CSV, the header being line 1
	Address          string `json:"address"`
	Path             string `json:"path"`
	Algorithm        string `json:"algorithm"`
	Curve            string `json:"curve"`
	VaultID          string `json:"vaultId"`
	Status           string `json:"status"` // match | label | mismatch | no-vault | invalid
	Chain            string `json:"chain"`  // chain of DerivedAddress
	DerivedAddress   string `json:"derivedAddress"`
	DerivedPublicKey string `json:"derivedPublicKey"`
	Message          string `json:"message"`
}

// VerifySourceResult is one uploaded input: a file, or a whole signer bundle.
type VerifySourceResult struct {
	Name      string `json:"name"`
	Kind      string `json:"kind"`
	Level     string `json:"level"`
	Error     string `json:"error,omitempty"`
	SignerID  string `json:"signerId,omitempty"`
	FileCount int    `json:"fileCount"`
}

// VerifyVaultResult is the verdict for one vault.
type VerifyVaultResult struct {
	VaultID          string                     `json:"vaultId"`
	Name             string                     `json:"name"`
	Threshold        int                        `json:"threshold"`
	CurrentRequestID string                     `json:"currentRequestId"`
	SharesCounted    int                        `json:"sharesCounted"`
	EdDSAShares      int                        `json:"eddsaShares"`
	HasEdDSA         bool                       `json:"hasEdDSA"`
	Status           string                     `json:"status"`
	Message          string                     `json:"message"`
	PendingSources   int                        `json:"pendingSources"`
	EthereumAddress  string                     `json:"ethereumAddress"`
	BitcoinAddress   string                     `json:"bitcoinAddress"` // native SegWit (bc1q) for the vault's ECDSA key
	EdDSAPublicKey   string                     `json:"eddsaPublicKey"`
	SolanaAddress    string                     `json:"solanaAddress"`
	XRPLAddress      string                     `json:"xrplAddress"`
	Contributions    []VerifyContributionResult `json:"contributions"`
}

// VerifyContributionResult is what one source (by index into Sources) holds for one vault.
type VerifyContributionResult struct {
	Source     int      `json:"source"`
	State      string   `json:"state"`
	RequestID  string   `json:"requestId"`
	Algorithms []string `json:"algorithms"`
}

// handleVerify reports which uploaded file holds a share for which vault, and whether each vault
// has enough current shares to be recovered. It takes the same form as /api/list-vaults, except
// that mnemonics and keys are optional: a file without one is checked by its header only. It never
// reconstructs a key. Per-file problems go in the report; only a malformed request is an error.
func (s *Server) handleVerify(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseMultipartForm(10 << 20); err != nil { // 10 MB in memory, the rest spills to disk
		http.Error(w, fmt.Sprintf("Failed to parse form: %v", err), http.StatusBadRequest)
		return
	}

	vaultsDataFiles, uploads, failures, reqCleanup, err := s.processUploadedFiles(r, true)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to process files: %v", err), http.StatusBadRequest)
		return
	}
	defer reqCleanup()
	defer vaultsDataFiles.Zeroize()

	privateKeysPEM, err := readPrivateKeysPEM(r)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to read private key: %v", err), http.StatusBadRequest)
		return
	}
	defer clearKeys(privateKeysPEM)

	presentation := recoverypipeline.ErrorPresentation{Path: filepath.Base, Err: fileutils.StripPathFromError}
	inputs, err := recoverypipeline.Discover(vaultsDataFiles, presentation)
	if err != nil {
		inputs.Close()
		http.Error(w, fmt.Sprintf("Failed to read files: %v", fileutils.StripPathFromError(err)), http.StatusBadRequest)
		return
	}
	defer inputs.Close()

	report, err := recoverypipeline.Verify(inputs, privateKeysPEM, presentation)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to verify files: %v", fileutils.StripPathFromError(err)), http.StatusInternalServerError)
		return
	}

	resp := buildVerifyResponse(report, uploads, time.Now())
	// Uploads that could not be opened never reached the pipeline. They go after its sources, so
	// the contributions' source indexes stay valid, and in the same per-file error shape.
	for _, f := range failures {
		resp.Sources = append(resp.Sources, VerifySourceResult{
			Name:  f.name,
			Kind:  sourceKindZipArchive,
			Level: string(recoverypipeline.VerifyLevelError),
			Error: f.err,
		})
	}
	resp.HDAddresses = verifyHDAddresses(r, report)

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		log.Printf("failed to encode verify response: %v", err)
	}
}

// verifyHDAddresses checks the optional "hdAddressesCSV" upload against the public keys the
// decrypted shares state. It returns nil when no CSV was sent. A CSV that cannot be read is
// reported in the result rather than failing the whole verification.
func verifyHDAddresses(r *http.Request, report *recoverypipeline.VerifyReport) *VerifyHDResult {
	if r.MultipartForm == nil || len(r.MultipartForm.File["hdAddressesCSV"]) == 0 {
		return nil
	}
	fileHeader := r.MultipartForm.File["hdAddressesCSV"][0]
	result := &VerifyHDResult{File: filepath.Base(fileHeader.Filename), Rows: []VerifyHDRow{}}

	file, err := fileHeader.Open()
	if err != nil {
		result.Error = fmt.Sprintf("the CSV could not be opened: %v", fileutils.StripPathFromError(err))
		return result
	}
	defer file.Close()
	raw, err := io.ReadAll(file)
	if err != nil {
		result.Error = fmt.Sprintf("the CSV could not be read: %v", fileutils.StripPathFromError(err))
		return result
	}
	records, err := hd.ParseCSVReader(bytes.NewReader(raw))
	if err != nil {
		result.Error = err.Error()
		return result
	}
	lines := csvRecordLines(raw)

	keys := make([]hd.VaultKey, 0, len(report.PublicKeys))
	for _, k := range report.PublicKeys {
		if k.EdDSA {
			keys = append(keys, hd.VaultKey{
				VaultID:   k.VaultID,
				Curve:     hd.CurveEdwards25519,
				PublicKey: edwards.NewPublicKey(k.Point.X(), k.Point.Y()).Serialize(),
			})
			continue
		}
		pub, _, err := getTSSPubKeyForEthereum(k.Point.X(), k.Point.Y())
		if err != nil {
			log.Printf("verify: skipping an unreadable ECDSA public key for vault %s: %v", k.VaultID, err)
			continue
		}
		keys = append(keys, hd.VaultKey{VaultID: k.VaultID, Curve: hd.CurveSecp256k1, PublicKey: pub.SerializeCompressed()})
	}

	for i, check := range hd.CheckRecords(records, keys) {
		line := i + 2 // header on line 1; only a fallback, csvRecordLines knows the real line
		if i < len(lines) {
			line = lines[i]
		}
		row := VerifyHDRow{
			Row:              line,
			Address:          check.Record.Address,
			Path:             check.Record.Path,
			Algorithm:        string(check.Record.Algorithm),
			Curve:            string(check.Record.Curve),
			VaultID:          check.VaultID,
			Status:           string(check.Status),
			DerivedPublicKey: check.DerivedPublicKey,
			Message:          check.Message,
		}
		if preferred := check.PreferredAddress(); preferred != nil {
			row.Chain = preferred.Chain
			row.DerivedAddress = preferred.Address
		}
		result.Rows = append(result.Rows, row)
	}
	return result
}

// csvRecordLines returns the line each data record of an HD addresses CSV starts on, in the order
// hd.ParseCSVReader returns the records. encoding/csv skips blank lines and lets a quoted field
// span lines, so a record's index does not give its line number. It reads the CSV with the same
// default reader settings as hd.ParseCSVReader, so the two agree record for record.
func csvRecordLines(raw []byte) []int {
	reader := csv.NewReader(bytes.NewReader(raw))
	if _, err := reader.Read(); err != nil { // the header
		return nil
	}
	var lines []int
	for {
		if _, err := reader.Read(); err != nil {
			return lines
		}
		line, _ := reader.FieldPos(0)
		lines = append(lines, line)
	}
}

// buildVerifyResponse turns the pipeline's report into the JSON contract: display names for the
// sources, and addresses derived from each vault's public keys.
func buildVerifyResponse(report *recoverypipeline.VerifyReport, uploads map[string]uploadedFile, checkedAt time.Time) VerifyResponse {
	resp := VerifyResponse{
		CheckedAt: checkedAt.UTC().Format(time.RFC3339),
		Sources:   make([]VerifySourceResult, 0, len(report.Sources)),
		Vaults:    make([]VerifyVaultResult, 0, len(report.Vaults)),
		Warnings:  append([]string{}, report.Warnings...),
	}

	for _, src := range report.Sources {
		// A bundle's source ID is already its uploaded base name; a direct file's is its temp path.
		name := filepath.Base(src.ID)
		kind := string(src.Kind)
		if upload, ok := uploads[src.ID]; ok {
			name = upload.name
			if upload.fromZip && (src.Kind == recoverypipeline.SourceKindMobileExport || src.Kind == recoverypipeline.SourceKindLegacyExport) {
				kind = sourceKindLegacyZipEntry
			}
		}
		resp.Sources = append(resp.Sources, VerifySourceResult{
			Name:      name,
			Kind:      kind,
			Level:     string(src.Level),
			Error:     src.Error,
			SignerID:  src.SignerID,
			FileCount: src.FileCount,
		})
	}

	for _, v := range report.Vaults {
		result := VerifyVaultResult{
			VaultID:          v.VaultID,
			Name:             v.Name,
			Threshold:        v.Threshold,
			CurrentRequestID: v.CurrentRequestID,
			SharesCounted:    v.SharesCounted,
			EdDSAShares:      v.EdDSAShares,
			HasEdDSA:         v.HasEdDSA,
			Status:           string(v.Status),
			Message:          v.Message,
			PendingSources:   v.PendingSources,
			Contributions:    make([]VerifyContributionResult, 0, len(v.Contributions)),
		}

		if v.ECDSAPub != nil {
			if pub, address, err := getTSSPubKeyForEthereum(v.ECDSAPub.X(), v.ECDSAPub.Y()); err == nil {
				result.EthereumAddress = address
				for _, a := range hd.AddressesForPublicKey(pub.SerializeCompressed(), hd.CurveSecp256k1) {
					if a.Chain == hd.ChainBitcoin {
						result.BitcoinAddress = a.Address
					}
				}
			} else {
				log.Printf("verify: could not derive an Ethereum address for vault %s: %v", v.VaultID, err)
			}
		}
		if v.EdDSAPub != nil {
			compressed := edwards.NewPublicKey(v.EdDSAPub.X(), v.EdDSAPub.Y()).SerializeCompressed()
			result.EdDSAPublicKey = hex.EncodeToString(compressed)
			if address, err := solana.DeriveSolanaAddress(compressed); err == nil {
				result.SolanaAddress = address
			} else {
				log.Printf("verify: could not derive a Solana address for vault %s: %v", v.VaultID, err)
			}
			// The same derivation the recover flow uses for its XRPL address.
			if address, err := xrpl.DeriveXRPLAddress(compressed); err == nil {
				result.XRPLAddress = address
			} else {
				log.Printf("verify: could not derive an XRP Ledger address for vault %s: %v", v.VaultID, err)
			}
		}

		for _, c := range v.Contributions {
			algorithms := c.Algorithms
			if algorithms == nil {
				algorithms = []string{}
			}
			result.Contributions = append(result.Contributions, VerifyContributionResult{
				Source:     c.Source,
				State:      string(c.State),
				RequestID:  c.RequestID,
				Algorithms: algorithms,
			})
		}
		resp.Vaults = append(resp.Vaults, result)
	}
	return resp
}
