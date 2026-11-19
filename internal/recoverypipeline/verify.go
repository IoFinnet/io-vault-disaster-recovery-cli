// Copyright (C) 2021 io finnet group, inc.
// SPDX-License-Identifier: AGPL-3.0-or-later
// Full license text available in LICENSE file in repository root.

package recoverypipeline

import (
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/IoFinnet/io-vault-disaster-recovery-cli/internal/dr"
	"github.com/iofinnet/tss-lib/v3/crypto"
	ecdsa_keygen "github.com/iofinnet/tss-lib/v3/tss/ecdsa/keygen"
	eddsa_keygen "github.com/iofinnet/tss-lib/v3/tss/schnorr/keygen"
)

// VerifyLevel says how far Verify could read one input source.
type VerifyLevel string

const (
	// VerifyLevelDecrypted means every file of the source was decrypted and its shares read.
	VerifyLevelDecrypted VerifyLevel = "decrypted"
	// VerifyLevelHeader means the source was read from its plaintext header only, because no
	// mnemonic or ML-KEM key was supplied for it. Header fields are unauthenticated hints.
	VerifyLevelHeader VerifyLevel = "header"
	// VerifyLevelError means the source (or one of its files) could not be read or decrypted.
	VerifyLevelError VerifyLevel = "error"
)

// VerifyStatus is the verdict for one vault.
type VerifyStatus string

const (
	VerifyStatusConflict         VerifyStatus = "conflict"
	VerifyStatusBelowThreshold   VerifyStatus = "below-threshold"
	VerifyStatusThresholdUnknown VerifyStatus = "threshold-unknown"
	VerifyStatusNotChecked       VerifyStatus = "not-checked"
	VerifyStatusRecoverable      VerifyStatus = "recoverable"
)

// verifyStatusSeverity orders vaults in a report, most urgent first.
var verifyStatusSeverity = map[VerifyStatus]int{
	VerifyStatusConflict:         0,
	VerifyStatusBelowThreshold:   1,
	VerifyStatusThresholdUnknown: 2,
	VerifyStatusNotChecked:       3,
	VerifyStatusRecoverable:      4,
}

// ContributionState says what one source holds for one vault.
type ContributionState string

const (
	// ContributionCounted: decrypted shares at the reshare a recovery would use.
	ContributionCounted ContributionState = "counted"
	// ContributionOtherReshare: decrypted shares from a reshare a recovery would not use.
	ContributionOtherReshare ContributionState = "other-reshare"
	// ContributionHeader: the source names the vault in its header but was not decrypted.
	ContributionHeader ContributionState = "header"
	// ContributionError: the source names the vault, but its share could not be decrypted or read.
	ContributionError ContributionState = "error"
	// ContributionConflict: decrypted shares for a vault whose files disagree with each other.
	ContributionConflict ContributionState = "conflict"
)

// contributionRank picks the state that represents a source holding several files for one vault
// (a bundle with files at two reshares): the lowest rank wins.
var contributionRank = map[ContributionState]int{
	ContributionCounted:      0,
	ContributionConflict:     1,
	ContributionOtherReshare: 2,
	ContributionError:        3,
	ContributionHeader:       4,
}

// SourceKind classifies an input source. A frontend may refine it (the web UI marks JSON files
// it extracted from a legacy ZIP archive), since only it knows where a file was uploaded from.
type SourceKind string

const (
	SourceKindMobileExport SourceKind = "mobile-export"
	SourceKindLegacyExport SourceKind = "legacy-export"
	SourceKindDRShare      SourceKind = "dr-share"
	SourceKindSignerBundle SourceKind = "signer-bundle"
)

// VerifySource is one input as the user supplied it: a direct file, or a whole signer bundle.
type VerifySource struct {
	// ID is the artifacts' SourceID: the input path for a direct file, the bundle's base name for
	// a bundle. It identifies the source to the caller; it is not meant for display as-is.
	ID        string
	Kind      SourceKind
	Level     VerifyLevel
	Error     string // set when Level is VerifyLevelError
	SignerID  string // bundle manifest's signer id, when known
	FileCount int
}

// VerifyContribution is what one source holds for one vault.
type VerifyContribution struct {
	Source     int // index into VerifyReport.Sources
	State      ContributionState
	RequestID  string
	Algorithms []string // "ECDSA" and/or "EdDSA", in that order
}

// VerifyVault is the verdict for one vault. It carries identifiers and public keys only.
type VerifyVault struct {
	VaultID          string
	Name             string // empty when no file records a name
	Threshold        int    // 0 when unknown
	CurrentRequestID string // the reshare a recovery would use
	SharesCounted    int    // distinct ECDSA shares at CurrentRequestID
	EdDSAShares      int    // distinct EdDSA shares at CurrentRequestID
	HasEdDSA         bool
	Status           VerifyStatus
	Message          string // explains a status other than recoverable
	PendingSources   int    // sources that name this vault but were read by header only

	// ECDSAPub and EdDSAPub are the vault's public keys as the counted shares state them, so a
	// frontend can show addresses for the user to compare. Nil when unknown or in conflict.
	ECDSAPub *crypto.ECPoint
	EdDSAPub *crypto.ECPoint

	Contributions []VerifyContribution
}

// VerifyReport is Verify's result. It never contains key material: no private key, no secret
// share, no mnemonic. Shares are decrypted only to read their vault, threshold, share id and
// public key, then wiped.
type VerifyReport struct {
	Sources  []VerifySource
	Vaults   []VerifyVault
	Warnings []string

	// PublicKeys lists every distinct vault public key a decrypted share stated, whatever the
	// vault's verdict, so a caller can tell which vault an xpub belongs to. A vault in conflict
	// can appear with more than one key per curve.
	PublicKeys []VaultPublicKey
}

// VaultPublicKey is one vault public key stated by a decrypted share.
type VaultPublicKey struct {
	VaultID string
	EdDSA   bool // false: ECDSA/secp256k1; true: EdDSA/Edwards25519
	Point   *crypto.ECPoint
}

// verifyRecord is Verify's working state for one artifact (one file).
type verifyRecord struct {
	source   int
	artifact Artifact
	isDR     bool
	legacy   bool // a JSON export in the legacy flat-nonce shape
	level    VerifyLevel
	err      string
	vaults   map[string]*verifyRecordVault

	// drEnvelope is a .dr file's plaintext envelope: its request id, previous request id and
	// algorithm. It is kept apart from vaults because the envelope's vaultId is unauthenticated and
	// may be missing or differ from the decrypted payload's, while the request link belongs to the
	// file whatever vault the payload names.
	drEnvelope *verifyRecordVault
}

// verifyRecordVault is what one artifact says about one vault.
type verifyRecordVault struct {
	requestID         string
	previousRequestID string // .dr files only, from the header
	algorithms        map[string]bool
	name              string
	threshold         int
	ecdsaIDs          []string
	eddsaIDs          []string
	ecdsaPub          *crypto.ECPoint   // the first stated key, shown for a below-threshold vault
	eddsaPub          *crypto.ECPoint   // likewise for EdDSA
	ecdsaPubs         []*crypto.ECPoint // every distinct stated key, for matching HD xpubs
	eddsaPubs         []*crypto.ECPoint

	// legacy marks a legacy flat-nonce entry, whose requestID is a reshare nonce, not a request id.
	legacy bool

	// err is set when this vault's entry in an otherwise readable multi-vault export could not be
	// decrypted or decoded. The file's other vaults still count; this one contributes nothing.
	err string
}

func newRecordVault(requestID string) *verifyRecordVault {
	return &verifyRecordVault{requestID: requestID, algorithms: map[string]bool{}}
}

// Verify reports which input holds a share for which vault, and whether each vault has enough
// current shares to be recovered. It never reconstructs a key.
//
// It reads in three passes. First, every file's plaintext header names its vaults and reshare, no
// secrets needed. Second, each file that has its mnemonic or an ML-KEM key goes through Prepare's
// listing pass on its own, so a wrong mnemonic or key marks that one file as an error instead of
// sinking the whole report. Third, per vault, Prepare's recovery-mode pass runs over the decrypted
// files only: that reuses the exact reshare selection and conflict checks a recovery would apply,
// then stops before reconstruction.
func Verify(inputs *InputSet, privateKeysPEM [][]byte, presentation ErrorPresentation) (*VerifyReport, error) {
	if inputs == nil {
		return nil, errors.New("verify: no input set")
	}

	report := &VerifyReport{Sources: []VerifySource{}, Vaults: []VerifyVault{}, Warnings: []string{}}
	records, sourceIndex := verifySources(inputs, report)

	// Pass 1: headers.
	for _, rec := range records {
		header, err := readVerifyHeader(rec.artifact.Path, rec.isDR)
		if err == nil && rec.isDR && len(header.vaults) == 0 && len(privateKeysPEM) == 0 {
			// Without a key the envelope's vaultId is the only way to attribute the file. With one,
			// the decrypted payload names the vault, as it does for recovery.
			err = errors.New("invalid .dr file: missing vaultId (add the ML-KEM-768 key to read the vault from the encrypted payload)")
		}
		if err != nil {
			rec.level = VerifyLevelError
			rec.err = presentation.err(err).Error()
			rec.vaults = map[string]*verifyRecordVault{}
			continue
		}
		rec.level = VerifyLevelHeader
		rec.legacy = header.legacy
		rec.vaults = header.vaults
		rec.drEnvelope = header.drEnvelope
		if header.legacy && report.Sources[rec.source].Kind == SourceKindMobileExport {
			report.Sources[rec.source].Kind = SourceKindLegacyExport
		}
	}

	// Pass 2: decrypt each file on its own.
	for _, rec := range records {
		if rec.level == VerifyLevelError {
			continue
		}
		locked := (rec.isDR && len(privateKeysPEM) == 0) || (!rec.isDR && rec.artifact.Mnemonics == "")
		if locked {
			continue
		}
		vaults, err := decryptVerifyRecord(rec.artifact, "", privateKeysPEM, presentation)
		if err != nil && !rec.isDR && len(rec.vaults) > 1 {
			// The listing pass stops at the first vault that fails, so retry vault by vault: one
			// damaged entry must not hide the usable shares the export holds for its other vaults. A
			// wrong mnemonic fails every vault, which still makes the whole file an error below.
			vaults, err = decryptVerifyRecordByVault(rec, privateKeysPEM, presentation)
		}
		if err != nil {
			// Keep the header's vaults, so the report still shows which vaults this file names.
			rec.level = VerifyLevelError
			rec.err = presentation.err(err).Error()
			continue
		}
		mergeVerifyHeader(rec, vaults)
		rec.vaults = vaults
		rec.level = VerifyLevelDecrypted
		for vID, rv := range vaults {
			for _, p := range rv.ecdsaPubs {
				report.addPublicKey(vID, false, p)
			}
			for _, p := range rv.eddsaPubs {
				report.addPublicKey(vID, true, p)
			}
		}
	}
	sort.SliceStable(report.PublicKeys, func(i, j int) bool {
		return report.PublicKeys[i].VaultID < report.PublicKeys[j].VaultID
	})

	// Pass 3: one verdict per vault.
	var selectionWarnings []Warning
	for _, vID := range verifyVaultIDs(records) {
		vv := VerifyVault{VaultID: vID}
		var holders, decryptedHolders []*verifyRecord
		for _, rec := range records {
			rv, ok := rec.vaults[vID]
			if !ok {
				continue
			}
			holders = append(holders, rec)
			if rec.level == VerifyLevelDecrypted && rv.err == "" {
				decryptedHolders = append(decryptedHolders, rec)
			}
			if vv.Name == "" {
				vv.Name = rv.name
			}
		}

		conflict := false
		if len(decryptedHolders) == 0 {
			vv.Status = VerifyStatusNotChecked
			vv.Message = notCheckedMessage(holders)
		} else {
			var warnings []Warning
			conflict, warnings = checkVerifyVault(&vv, decryptedHolders, inputs.bundles, privateKeysPEM, presentation)
			selectionWarnings = append(selectionWarnings, warnings...)
		}

		vv.Contributions = verifyContributions(vID, records, len(report.Sources), vv.CurrentRequestID, conflict)
		for _, c := range vv.Contributions {
			if c.State == ContributionHeader {
				vv.PendingSources++
			}
		}
		report.Vaults = append(report.Vaults, vv)
	}

	setVerifySourceLevels(report, records, sourceIndex)

	sort.SliceStable(report.Vaults, func(i, j int) bool {
		a, b := report.Vaults[i], report.Vaults[j]
		if sa, sb := verifyStatusSeverity[a.Status], verifyStatusSeverity[b.Status]; sa != sb {
			return sa < sb
		}
		if na, nb := strings.ToLower(a.Name), strings.ToLower(b.Name); na != nb {
			return na < nb
		}
		return a.VaultID < b.VaultID
	})

	seen := make(map[string]bool)
	for _, w := range append(append([]Warning(nil), inputs.warnings...), selectionWarnings...) {
		line := formatVerifyWarning(w, presentation)
		if !seen[line] {
			seen[line] = true
			report.Warnings = append(report.Warnings, line)
		}
	}
	return report, nil
}

// addPublicKey records a vault public key once, skipping nil and duplicate points.
func (r *VerifyReport) addPublicKey(vaultID string, eddsa bool, point *crypto.ECPoint) {
	if point == nil {
		return
	}
	for _, k := range r.PublicKeys {
		if k.VaultID == vaultID && k.EdDSA == eddsa && k.Point.Equals(point) {
			return
		}
	}
	r.PublicKeys = append(r.PublicKeys, VaultPublicKey{VaultID: vaultID, EdDSA: eddsa, Point: point})
}

// verifySources lists the sources in input order, one record per artifact. A bundle is one
// source however many files it holds; a bundle whose files were all ignored still appears, so
// the user sees that it contributed nothing.
func verifySources(inputs *InputSet, report *VerifyReport) ([]*verifyRecord, map[string]int) {
	sourceIndex := make(map[string]int)
	records := make([]*verifyRecord, 0, len(inputs.artifacts))
	for _, a := range inputs.artifacts {
		idx, ok := sourceIndex[a.SourceID]
		if !ok {
			idx = len(report.Sources)
			sourceIndex[a.SourceID] = idx
			report.Sources = append(report.Sources, VerifySource{ID: a.SourceID, Kind: sourceKindFor(a)})
		}
		report.Sources[idx].FileCount++
		records = append(records, &verifyRecord{source: idx, artifact: a, isDR: isDRPath(a.Path)})
	}
	for _, b := range inputs.bundles {
		idx, ok := sourceIndex[b.SourceID]
		if !ok {
			idx = len(report.Sources)
			sourceIndex[b.SourceID] = idx
			report.Sources = append(report.Sources, VerifySource{
				ID:    b.SourceID,
				Kind:  SourceKindSignerBundle,
				Level: VerifyLevelError,
				Error: "This bundle holds no usable .dr files.",
			})
		}
		report.Sources[idx].SignerID = b.SignerID
	}
	return records, sourceIndex
}

// setVerifySourceLevels rolls each source's files up into one level: any error wins (including one
// vault of a multi-vault export that could not be decrypted), then any header-only file, otherwise
// the source was fully decrypted.
func setVerifySourceLevels(report *VerifyReport, records []*verifyRecord, sourceIndex map[string]int) {
	type rollup struct {
		files     int
		headers   int
		firstErr  string
		hasErrors bool
	}
	rollups := make([]rollup, len(report.Sources))
	for _, rec := range records {
		r := &rollups[rec.source]
		r.files++
		switch rec.level {
		case VerifyLevelError:
			if !r.hasErrors {
				r.firstErr = rec.err
			}
			r.hasErrors = true
		case VerifyLevelHeader:
			r.headers++
		case VerifyLevelDecrypted:
			for _, vID := range sortedVaultKeys(rec.vaults) {
				if msg := rec.vaults[vID].err; msg != "" {
					if !r.hasErrors {
						r.firstErr = msg
					}
					r.hasErrors = true
				}
			}
		}
	}
	for _, idx := range sourceIndex {
		src := &report.Sources[idx]
		r := rollups[idx]
		if r.files == 0 {
			continue // a bundle with no usable files keeps the level verifySources gave it
		}
		switch {
		case r.hasErrors:
			src.Level = VerifyLevelError
			src.Error = r.firstErr
		case r.headers > 0:
			src.Level = VerifyLevelHeader
		default:
			src.Level = VerifyLevelDecrypted
		}
	}
}

// verifyHeader is what a file's plaintext says about it.
type verifyHeader struct {
	vaults map[string]*verifyRecordVault
	legacy bool
	// drEnvelope is set for a .dr file. Its vault appears in vaults only when the envelope names
	// one; a key can still attribute the file through its decrypted payload.
	drEnvelope *verifyRecordVault
}

// readVerifyHeader reads what a file says about its vaults without decrypting it.
func readVerifyHeader(path string, isDR bool) (verifyHeader, error) {
	header := verifyHeader{vaults: make(map[string]*verifyRecordVault)}
	raw, err := os.ReadFile(path)
	if err != nil {
		return header, fmt.Errorf("failed to read file: %w", err)
	}

	if isDR {
		envelope, err := dr.ParseEnvelope(raw)
		if err != nil {
			return header, err
		}
		rv := newRecordVault(envelope.RequestId)
		rv.previousRequestID = envelope.PreviousRequestId
		if alg := algorithmLabel(envelope.Algo); alg != "" {
			rv.algorithms[alg] = true
		}
		header.drEnvelope = rv
		if envelope.VaultId != "" {
			header.vaults[envelope.VaultId] = rv
		}
		return header, nil
	}

	var saved SavedData
	if err := json.Unmarshal(raw, &saved); err != nil {
		return header, fmt.Errorf("not a recognised io.vault backup file: %w", err)
	}
	if len(saved.Vaults) == 0 {
		return header, errors.New("not a recognised io.vault backup file: it holds no vaults")
	}
	for vID, entry := range saved.Vaults {
		requestID := entry.CurrentRequestID
		if entry.IsLegacy {
			header.legacy = true
			highest := -1
			for nonce := range entry.LegacyByNonce {
				if nonce > highest {
					highest = nonce
				}
			}
			if highest >= 0 {
				requestID = strconv.Itoa(highest)
			}
		}
		rv := newRecordVault(requestID)
		rv.legacy = entry.IsLegacy
		header.vaults[vID] = rv
	}
	return header, nil
}

// mergeVerifyHeader carries what only the plaintext header records into the decrypted vaults: the
// algorithms it names, whether a JSON entry is legacy and, for a .dr file, its previous request
// id. A .dr file's request link is
// attached to the vault its authenticated payload names, even when the unauthenticated envelope
// names another vault or none, because Prepare walks the chain with that same link.
func mergeVerifyHeader(rec *verifyRecord, decrypted map[string]*verifyRecordVault) {
	if rec.isDR {
		if rec.drEnvelope == nil {
			return
		}
		for _, dv := range decrypted {
			dv.previousRequestID = rec.drEnvelope.previousRequestID
			for alg := range rec.drEnvelope.algorithms {
				dv.algorithms[alg] = true
			}
		}
		return
	}
	for vID, header := range rec.vaults {
		if dv, ok := decrypted[vID]; ok {
			dv.legacy = header.legacy
			for alg := range header.algorithms {
				dv.algorithms[alg] = true
			}
		}
	}
}

// decryptVerifyRecord runs one Prepare pass over one artifact and keeps only identifiers and
// public keys from it: the listing pass when vaultID is empty, else a recovery-mode pass for that
// vault alone. Every secret share value the pass decrypts is wiped before returning.
func decryptVerifyRecord(a Artifact, vaultID string, privateKeysPEM [][]byte, presentation ErrorPresentation) (map[string]*verifyRecordVault, error) {
	res, err := Prepare(&InputSet{artifacts: []Artifact{a}}, Options{
		VaultID: vaultID, PrivateKeysPEM: privateKeysPEM, Presentation: presentation, quiet: true, secrets: &secretTracker{},
	})
	if err != nil {
		return nil, err
	}
	defer wipeResultShares(res)

	out := make(map[string]*verifyRecordVault, len(res.Vaults))
	for vID, cv := range res.Vaults {
		if cv == nil {
			continue
		}
		rv := newRecordVault(cv.LastRequestID)
		rv.threshold = cv.Quroum
		rv.name = knownVaultName(vID, cv.Name)
		for _, s := range res.SharesECDSA[vID] {
			if s == nil {
				continue
			}
			rv.algorithms["ECDSA"] = true
			rv.ecdsaIDs = append(rv.ecdsaIDs, shareIDKey(s.ShareID))
			rv.ecdsaPubs = appendDistinctPoint(rv.ecdsaPubs, s.ECDSAPub)
		}
		for _, s := range res.SharesEdDSA[vID] {
			if s == nil {
				continue
			}
			rv.algorithms["EdDSA"] = true
			rv.eddsaIDs = append(rv.eddsaIDs, shareIDKey(s.ShareID))
			rv.eddsaPubs = appendDistinctPoint(rv.eddsaPubs, s.EDDSAPub)
		}
		if len(rv.ecdsaPubs) > 0 {
			rv.ecdsaPub = rv.ecdsaPubs[0]
		}
		if len(rv.eddsaPubs) > 0 {
			rv.eddsaPub = rv.eddsaPubs[0]
		}
		out[vID] = rv
	}
	return out, nil
}

// decryptVerifyRecordByVault decrypts a multi-vault export one vault at a time, after its listing
// pass failed. A vault that fails keeps its header entry with err set; the others are read as
// usual. If no vault can be read (a wrong mnemonic, say), the first error is the whole file's.
func decryptVerifyRecordByVault(rec *verifyRecord, privateKeysPEM [][]byte, presentation ErrorPresentation) (map[string]*verifyRecordVault, error) {
	out := make(map[string]*verifyRecordVault, len(rec.vaults))
	var firstErr error
	readAny := false
	for _, vID := range sortedVaultKeys(rec.vaults) {
		vaults, err := decryptVerifyRecord(rec.artifact, vID, privateKeysPEM, presentation)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			failed := newRecordVault(rec.vaults[vID].requestID)
			failed.err = presentation.err(err).Error()
			out[vID] = failed
			continue
		}
		readAny = true
		if rv, ok := vaults[vID]; ok {
			out[vID] = rv
		}
	}
	if !readAny && firstErr != nil {
		return nil, firstErr
	}
	return out, nil
}

// checkVerifyVault fills in the verdict for a vault that at least one decrypted file holds. It
// reports whether the vault's files conflict, plus any reshare-selection warnings.
//
// Only the files that hold this vault go into Prepare. Prepare would ignore the others anyway, but
// it decrypts a .dr file before it can tell which vault the file is for, so passing every file
// would decrypt each of them again for every vault in the report.
func checkVerifyVault(vv *VerifyVault, holders []*verifyRecord, bundles []BundleInfo,
	privateKeysPEM [][]byte, presentation ErrorPresentation) (conflict bool, warnings []Warning) {

	vID := vv.VaultID
	artifacts := make([]Artifact, 0, len(holders))
	for _, rec := range holders {
		artifacts = append(artifacts, rec.artifact)
	}
	res, err := Prepare(&InputSet{artifacts: artifacts, bundles: bundles}, Options{
		VaultID: vID, PrivateKeysPEM: privateKeysPEM, Presentation: presentation, quiet: true, secrets: &secretTracker{},
	})
	if err != nil {
		if errors.Is(err, ErrNotEnoughShares) {
			if requestID, thresholds, ok := thresholdDisagreement(vID, holders); ok {
				vv.Status = VerifyStatusConflict
				vv.Message = fmt.Sprintf("These files state different thresholds (%s) for the same reshare of this vault (%s), so their shares cannot be combined.",
					joinInts(thresholds), requestID)
				return true, nil
			}
			belowThresholdFromRecords(vv, holders)
			return false, nil
		}
		vv.Status = VerifyStatusConflict
		vv.Message = presentation.err(err).Error()
		return true, nil
	}
	defer wipeResultShares(res)
	warnings = res.Warnings

	cv := res.Vaults[vID]
	if cv == nil {
		vv.Status = VerifyStatusNotChecked
		vv.Message = "None of the unlocked files hold usable shares for this vault."
		return false, warnings
	}
	vv.Threshold = cv.Quroum
	vv.CurrentRequestID = cv.LastRequestID
	if vv.Name == "" {
		vv.Name = knownVaultName(vID, cv.Name)
	}
	vv.HasEdDSA = res.HasEdDSA[vID]

	ecdsaIDs, dupECDSA := distinctShareIDs(res.SharesECDSA[vID])
	eddsaIDs, dupEdDSA := eddsaShareIDs(res.SharesEdDSA[vID])
	vv.SharesCounted = len(ecdsaIDs)
	vv.EdDSAShares = len(eddsaIDs)
	if dupECDSA || dupEdDSA {
		vv.Status = VerifyStatusConflict
		vv.Message = "Two files hold the same share. Remove the duplicate backup and verify again."
		return true, warnings
	}

	// Every share the recovery pass would use must come from a file at the chosen reshare. If not,
	// the pass merged shares from two reshares (legacy exports carry no chain to resolve this),
	// and reconstruction would produce a wrong key.
	atChosen := make(map[string]bool)
	for _, rec := range holders {
		if rv := rec.vaults[vID]; rv.requestID == vv.CurrentRequestID {
			for _, id := range rv.ecdsaIDs {
				atChosen[id] = true
			}
		}
	}
	for id := range ecdsaIDs {
		if !atChosen[id] {
			vv.Status = VerifyStatusConflict
			vv.Message = "These files hold shares from different reshares of this vault. Keep only the backups made after its latest reshare."
			return true, warnings
		}
	}

	ecdsaPub, ok := agreedPublicKey(ecdsaPubs(res.SharesECDSA[vID]))
	if !ok {
		vv.Status = VerifyStatusConflict
		vv.Message = "These shares disagree on the vault's ECDSA public key, so they are not from the same vault key."
		return true, warnings
	}
	eddsaPub, ok := agreedPublicKey(eddsaPubs(res.SharesEdDSA[vID]))
	if !ok {
		vv.Status = VerifyStatusConflict
		vv.Message = "These shares disagree on the vault's EdDSA public key, so they are not from the same vault key."
		return true, warnings
	}
	vv.ECDSAPub, vv.EdDSAPub = ecdsaPub, eddsaPub

	switch {
	case res.MobileVaults[vID] && !res.MobileFileThreshold[vID]:
		vv.Status = VerifyStatusThresholdUnknown
		vv.Message = "This vault's mobile app backup does not record its threshold (a v4 export). Re-export it with the current app, or enter the threshold when you recover."
	case vv.Threshold < 1:
		vv.Status = VerifyStatusThresholdUnknown
		vv.Message = "None of these files record this vault's threshold. Enter it when you recover."
	case vv.HasEdDSA && vv.EdDSAShares != vv.SharesCounted:
		vv.Status = VerifyStatusBelowThreshold
		vv.Message = fmt.Sprintf("Found %d ECDSA and %d EdDSA shares. Each signer's ECDSA and EdDSA backups are needed together.",
			vv.SharesCounted, vv.EdDSAShares)
	case vv.SharesCounted >= vv.Threshold:
		vv.Status = VerifyStatusRecoverable
	default:
		vv.Status = VerifyStatusBelowThreshold
		vv.Message = belowThresholdMessage(vv.SharesCounted, vv.EdDSAShares, vv.HasEdDSA, vv.Threshold)
	}
	return false, warnings
}

// thresholdDisagreement finds a reshare at which the decrypted files state different thresholds.
// Prepare compares thresholds only once it has selected a reshare with enough shares, so when none
// has enough it stops before that check. Without this, Verify would ask for another signer although
// recovery would still fail on the mismatch once one was added.
//
// It mirrors which shares Prepare combines at a .dr reshare (see jsonExtras): .dr and mobile files
// at that request id, plus legacy exports, which carry no request id and count at the mobile
// export's reshare if there is one, else at every reshare.
func thresholdDisagreement(vID string, holders []*verifyRecord) (requestID string, thresholds []int, found bool) {
	drRequests := make(map[string]bool)
	mobileRequestID := ""
	var legacyThresholds []int
	for _, rec := range holders {
		rv := rec.vaults[vID]
		switch {
		case rec.isDR:
			drRequests[rv.requestID] = true
		case rv.legacy:
			if rv.threshold > 0 {
				legacyThresholds = append(legacyThresholds, rv.threshold)
			}
		default:
			mobileRequestID = rv.requestID
		}
	}

	requestIDs := make([]string, 0, len(drRequests))
	for reqID := range drRequests {
		requestIDs = append(requestIDs, reqID)
	}
	sort.Strings(requestIDs)
	for _, reqID := range requestIDs {
		stated := make(map[int]bool)
		for _, rec := range holders {
			rv := rec.vaults[vID]
			if !rv.legacy && rv.requestID == reqID && rv.threshold > 0 {
				stated[rv.threshold] = true
			}
		}
		if mobileRequestID == "" || mobileRequestID == reqID {
			for _, t := range legacyThresholds {
				stated[t] = true
			}
		}
		if len(stated) > 1 {
			for t := range stated {
				thresholds = append(thresholds, t)
			}
			sort.Ints(thresholds)
			return reqID, thresholds, true
		}
	}
	return "", nil, false
}

func joinInts(values []int) string {
	parts := make([]string, len(values))
	for i, v := range values {
		parts[i] = strconv.Itoa(v)
	}
	return strings.Join(parts, " and ")
}

// belowThresholdFromRecords fills in a vault whose .dr chain has no reshare with enough shares.
// It reports the chain head, the reshare a recovery needs, from what each decrypted file said.
func belowThresholdFromRecords(vv *VerifyVault, holders []*verifyRecord) {
	vID := vv.VaultID
	chain := make(drReshareChain)
	for _, rec := range holders {
		rv := rec.vaults[vID]
		if !rec.isDR || rv.requestID == "" {
			continue
		}
		if _, ok := chain[rv.requestID]; !ok {
			chain[rv.requestID] = &drVaultShares{threshold: rv.threshold, previousRequestId: rv.previousRequestID}
		}
	}
	head := chainHeadID(chain)

	ecdsaIDs := make(map[string]bool)
	eddsaIDs := make(map[string]bool)
	for _, rec := range holders {
		rv := rec.vaults[vID]
		if rv.requestID != head {
			continue
		}
		for _, id := range rv.ecdsaIDs {
			ecdsaIDs[id] = true
		}
		for _, id := range rv.eddsaIDs {
			eddsaIDs[id] = true
		}
		if rv.threshold > vv.Threshold {
			vv.Threshold = rv.threshold
		}
		if vv.ECDSAPub == nil {
			vv.ECDSAPub = rv.ecdsaPub
		}
		if vv.EdDSAPub == nil {
			vv.EdDSAPub = rv.eddsaPub
		}
	}

	vv.CurrentRequestID = head
	vv.SharesCounted = len(ecdsaIDs)
	vv.EdDSAShares = len(eddsaIDs)
	vv.HasEdDSA = len(eddsaIDs) > 0
	vv.Status = VerifyStatusBelowThreshold
	vv.Message = belowThresholdMessage(vv.SharesCounted, vv.EdDSAShares, vv.HasEdDSA, vv.Threshold)
}

// belowThresholdMessage explains a shortfall at the current reshare. When the ECDSA count alone
// tells the story (no EdDSA shortfall, or one of the same size, as when whole signers are missing)
// it keeps the plain wording; otherwise each short curve is named with its own count, so the
// message never asks for a negative number of signers.
func belowThresholdMessage(ecdsa, eddsa int, hasEdDSA bool, threshold int) string {
	if threshold < 1 {
		return fmt.Sprintf("%d shares found at the current reshare, which is not enough to recover this vault.", ecdsa)
	}
	ecdsaShort := ecdsa < threshold
	eddsaShort := hasEdDSA && eddsa < threshold
	switch {
	case ecdsaShort && (!eddsaShort || eddsa == ecdsa):
		return fmt.Sprintf("%d of %d required shares found at the current reshare. Add backups from %s.",
			ecdsa, threshold, moreSigners(threshold-ecdsa))
	case eddsaShort && !ecdsaShort:
		return fmt.Sprintf("%d of %d required EdDSA shares found at the current reshare. Add EdDSA backups from %s.",
			eddsa, threshold, moreSigners(threshold-eddsa))
	case ecdsaShort && eddsaShort:
		return fmt.Sprintf("%d of %d required ECDSA shares and %d of %d required EdDSA shares found at the current reshare. Add backups from %s.",
			ecdsa, threshold, eddsa, threshold, moreSigners(threshold-min(ecdsa, eddsa)))
	default:
		return "Not enough shares were found at the current reshare to recover this vault."
	}
}

func moreSigners(n int) string {
	if n == 1 {
		return "1 more signer"
	}
	return fmt.Sprintf("%d more signers", n)
}

func notCheckedMessage(holders []*verifyRecord) string {
	for _, rec := range holders {
		if rec.level == VerifyLevelHeader {
			return "Found by file header only. Add the mnemonic or ML-KEM key for its files to check its threshold and shares."
		}
	}
	return "The files that name this vault could not be decrypted or read. Each file's error says why."
}

// verifyContributions rolls each source's files up into one contribution for vault vID.
func verifyContributions(vID string, records []*verifyRecord, sources int, chosen string, conflict bool) []VerifyContribution {
	type rollup struct {
		seen      bool
		state     ContributionState
		requestID string
		algos     map[string]bool
	}
	rollups := make([]rollup, sources)
	for _, rec := range records {
		rv, ok := rec.vaults[vID]
		if !ok {
			continue
		}
		state := contributionState(rec, rv, chosen, conflict)
		r := &rollups[rec.source]
		if !r.seen || contributionRank[state] < contributionRank[r.state] {
			r.state = state
			r.requestID = rv.requestID
		}
		r.seen = true
		if r.algos == nil {
			r.algos = make(map[string]bool)
		}
		for alg := range rv.algorithms {
			r.algos[alg] = true
		}
	}

	out := []VerifyContribution{}
	for i, r := range rollups {
		if !r.seen {
			continue
		}
		out = append(out, VerifyContribution{Source: i, State: r.state, RequestID: r.requestID, Algorithms: sortedAlgorithms(r.algos)})
	}
	return out
}

func contributionState(rec *verifyRecord, rv *verifyRecordVault, chosen string, conflict bool) ContributionState {
	switch rec.level {
	case VerifyLevelHeader:
		return ContributionHeader
	case VerifyLevelError:
		return ContributionError
	}
	if rv.err != "" {
		return ContributionError
	}
	if conflict {
		return ContributionConflict
	}
	if chosen != "" && rv.requestID == chosen {
		return ContributionCounted
	}
	return ContributionOtherReshare
}

// verifyVaultIDs returns every vault any file names, sorted.
func verifyVaultIDs(records []*verifyRecord) []string {
	seen := make(map[string]bool)
	var ids []string
	for _, rec := range records {
		for vID := range rec.vaults {
			if !seen[vID] {
				seen[vID] = true
				ids = append(ids, vID)
			}
		}
	}
	sort.Strings(ids)
	return ids
}

func sourceKindFor(a Artifact) SourceKind {
	switch {
	case a.SourceID != a.Path:
		return SourceKindSignerBundle // expandBundle names its artifacts after the bundle
	case isDRPath(a.Path):
		return SourceKindDRShare
	default:
		return SourceKindMobileExport // refined to legacy once its header is read
	}
}

func isDRPath(path string) bool {
	return strings.EqualFold(filepath.Ext(path), ".dr")
}

func algorithmLabel(algo string) string {
	switch strings.ToUpper(algo) {
	case "ECDSA":
		return "ECDSA"
	case "EDDSA":
		return "EdDSA"
	}
	return ""
}

func sortedAlgorithms(algos map[string]bool) []string {
	out := []string{}
	for _, alg := range []string{"ECDSA", "EdDSA"} {
		if algos[alg] {
			out = append(out, alg)
		}
	}
	return out
}

// knownVaultName drops the placeholder name the pipeline gives a vault no file named (its id).
func knownVaultName(vID, name string) string {
	if name == vID {
		return ""
	}
	return name
}

func shareIDKey(id *big.Int) string {
	if id == nil {
		return ""
	}
	return id.String()
}

// distinctShareIDs returns the set of ECDSA share ids, and whether any id appears twice.
func distinctShareIDs(shares []*ecdsa_keygen.LocalPartySaveData) (map[string]bool, bool) {
	ids := make(map[string]bool, len(shares))
	dup := false
	for _, s := range shares {
		if s == nil {
			continue
		}
		key := shareIDKey(s.ShareID)
		if ids[key] {
			dup = true
		}
		ids[key] = true
	}
	return ids, dup
}

// eddsaShareIDs is distinctShareIDs for EdDSA shares.
func eddsaShareIDs(shares []*eddsa_keygen.LocalPartySaveData) (map[string]bool, bool) {
	ids := make(map[string]bool, len(shares))
	dup := false
	for _, s := range shares {
		if s == nil {
			continue
		}
		key := shareIDKey(s.ShareID)
		if ids[key] {
			dup = true
		}
		ids[key] = true
	}
	return ids, dup
}

func ecdsaPubs(shares []*ecdsa_keygen.LocalPartySaveData) []*crypto.ECPoint {
	var pubs []*crypto.ECPoint
	for _, s := range shares {
		if s != nil && s.ECDSAPub != nil {
			pubs = append(pubs, s.ECDSAPub)
		}
	}
	return pubs
}

func eddsaPubs(shares []*eddsa_keygen.LocalPartySaveData) []*crypto.ECPoint {
	var pubs []*crypto.ECPoint
	for _, s := range shares {
		if s != nil && s.EDDSAPub != nil {
			pubs = append(pubs, s.EDDSAPub)
		}
	}
	return pubs
}

// agreedPublicKey returns the one public key all shares state, or false if they disagree. No
// shares means no key, which is not a disagreement.
func agreedPublicKey(pubs []*crypto.ECPoint) (*crypto.ECPoint, bool) {
	if len(pubs) == 0 {
		return nil, true
	}
	for _, p := range pubs[1:] {
		if !pubs[0].Equals(p) {
			return nil, false
		}
	}
	return pubs[0], true
}

// sortedVaultKeys returns a record's vault ids in order, so per-vault work is deterministic.
func sortedVaultKeys(vaults map[string]*verifyRecordVault) []string {
	keys := make([]string, 0, len(vaults))
	for vID := range vaults {
		keys = append(keys, vID)
	}
	sort.Strings(keys)
	return keys
}

// appendDistinctPoint appends p unless it is nil or already listed.
func appendDistinctPoint(points []*crypto.ECPoint, p *crypto.ECPoint) []*crypto.ECPoint {
	if p == nil {
		return points
	}
	for _, q := range points {
		if q.Equals(p) {
			return points
		}
	}
	return append(points, p)
}

// wipeResultShares zeroes every secret share value a Prepare result holds, once Verify has read
// the identifiers it needs.
func wipeResultShares(res *Result) {
	if res == nil {
		return
	}
	for _, shares := range res.SharesECDSA {
		for _, s := range shares {
			if s != nil {
				zeroBigInt(s.Xi)
			}
		}
	}
	for _, shares := range res.SharesEdDSA {
		for _, s := range shares {
			if s != nil {
				zeroBigInt(s.Xi)
			}
		}
	}
}

// zeroBigInt overwrites x's current backing words, then sets it to zero. Earlier copies big.Int
// made while computing x are out of reach, so this is best effort, like the rest of the tool's key
// hygiene.
func zeroBigInt(x *big.Int) {
	if x == nil {
		return
	}
	words := x.Bits()
	clear(words[:cap(words)])
	x.SetInt64(0)
}

// secretTracker records the secret share values (Xi) a verify-only Prepare pass decrypts, so the
// pass can zero every value it does not hand back. Values are recorded as soon as they are decoded,
// before any check can drop them, and shares decoded from the same payload share their Xi pointer,
// so recording the payload covers the save data built from it. A tracker serves one Prepare pass.
// A nil tracker records nothing, which is how the recovery path runs.
type secretTracker struct {
	xis []*big.Int
}

// addShare records a decoded ECDSA or EdDSA share's secret value.
func (t *secretTracker) addShare(share any) {
	if t == nil {
		return
	}
	if xi, _ := secretOf(share); xi != nil {
		t.xis = append(t.xis, xi)
	}
}

// addDR records every secret value in a decrypted .dr payload.
func (t *secretTracker) addDR(p *dr.Parsed) {
	if t == nil || p == nil {
		return
	}
	if p.ECDSA != nil {
		for _, s := range p.ECDSA.Data {
			if s != nil && s.Xi != nil {
				t.xis = append(t.xis, s.Xi)
			}
		}
	}
	if p.EdDSA != nil {
		for _, s := range p.EdDSA.Data {
			if s != nil && s.Xi != nil {
				t.xis = append(t.xis, s.Xi)
			}
		}
	}
}

// wipeExcept zeroes every recorded value except the secrets of the shares in the given pools,
// which the pass hands back to its caller. Nil pools wipe everything.
func (t *secretTracker) wipeExcept(ecdsa VaultAllSharesECDSA, eddsa VaultAllSharesEdDSA) {
	if t == nil {
		return
	}
	kept := make(map[*big.Int]bool)
	for _, shares := range ecdsa {
		for _, s := range shares {
			if s != nil && s.Xi != nil {
				kept[s.Xi] = true
			}
		}
	}
	for _, shares := range eddsa {
		for _, s := range shares {
			if s != nil && s.Xi != nil {
				kept[s.Xi] = true
			}
		}
	}
	for _, xi := range t.xis {
		if !kept[xi] {
			zeroBigInt(xi)
		}
	}
}

func formatVerifyWarning(w Warning, presentation ErrorPresentation) string {
	var b strings.Builder
	if w.SourceID != "" {
		b.WriteString(presentation.path(w.SourceID))
		b.WriteString(": ")
	}
	if w.VaultID != "" {
		fmt.Fprintf(&b, "vault %s: ", w.VaultID)
	}
	b.WriteString(w.Message)
	return b.String()
}
