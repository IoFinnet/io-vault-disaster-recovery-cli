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
	// ContributionError: the source names the vault but could not be decrypted.
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
	ecdsaPub          *crypto.ECPoint
	eddsaPub          *crypto.ECPoint
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
		vaults, legacy, err := readVerifyHeader(rec.artifact.Path, rec.isDR)
		if err != nil {
			rec.level = VerifyLevelError
			rec.err = presentation.err(err).Error()
			rec.vaults = map[string]*verifyRecordVault{}
			continue
		}
		rec.level = VerifyLevelHeader
		rec.legacy = legacy
		rec.vaults = vaults
		if legacy && report.Sources[rec.source].Kind == SourceKindMobileExport {
			report.Sources[rec.source].Kind = SourceKindLegacyExport
		}
	}

	// Pass 2: decrypt each file on its own.
	var decrypted []Artifact
	for _, rec := range records {
		if rec.level == VerifyLevelError {
			continue
		}
		locked := (rec.isDR && len(privateKeysPEM) == 0) || (!rec.isDR && rec.artifact.Mnemonics == "")
		if locked {
			continue
		}
		vaults, err := decryptVerifyRecord(rec.artifact, privateKeysPEM, presentation)
		if err != nil {
			// Keep the header's vaults, so the report still shows which vaults this file names.
			rec.level = VerifyLevelError
			rec.err = presentation.err(err).Error()
			continue
		}
		for vID, header := range rec.vaults {
			if dv, ok := vaults[vID]; ok {
				dv.previousRequestID = header.previousRequestID
				for alg := range header.algorithms {
					dv.algorithms[alg] = true
				}
			}
		}
		rec.vaults = vaults
		rec.level = VerifyLevelDecrypted
		decrypted = append(decrypted, rec.artifact)
		for vID, rv := range vaults {
			report.addPublicKey(vID, false, rv.ecdsaPub)
			report.addPublicKey(vID, true, rv.eddsaPub)
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
			if rec.level == VerifyLevelDecrypted {
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
			conflict, warnings = checkVerifyVault(&vv, decryptedHolders, decrypted, inputs.bundles, privateKeysPEM, presentation)
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

// setVerifySourceLevels rolls each source's files up into one level: any error wins, then any
// header-only file, otherwise the source was fully decrypted.
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

// readVerifyHeader reads what a file says about its vaults without decrypting it.
func readVerifyHeader(path string, isDR bool) (vaults map[string]*verifyRecordVault, legacy bool, err error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, false, fmt.Errorf("failed to read file: %w", err)
	}
	vaults = make(map[string]*verifyRecordVault)

	if isDR {
		envelope, err := dr.ParseEnvelope(raw)
		if err != nil {
			return nil, false, err
		}
		if envelope.VaultId == "" {
			return nil, false, errors.New("invalid .dr file: missing vaultId")
		}
		rv := newRecordVault(envelope.RequestId)
		rv.previousRequestID = envelope.PreviousRequestId
		if alg := algorithmLabel(envelope.Algo); alg != "" {
			rv.algorithms[alg] = true
		}
		vaults[envelope.VaultId] = rv
		return vaults, false, nil
	}

	var saved SavedData
	if err := json.Unmarshal(raw, &saved); err != nil {
		return nil, false, fmt.Errorf("not a recognised io.vault backup file: %w", err)
	}
	if len(saved.Vaults) == 0 {
		return nil, false, errors.New("not a recognised io.vault backup file: it holds no vaults")
	}
	for vID, entry := range saved.Vaults {
		requestID := entry.CurrentRequestID
		if entry.IsLegacy {
			legacy = true
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
		vaults[vID] = newRecordVault(requestID)
	}
	return vaults, legacy, nil
}

// decryptVerifyRecord runs Prepare's listing pass over one artifact and keeps only identifiers
// and public keys from it. The secret share values are wiped before returning.
func decryptVerifyRecord(a Artifact, privateKeysPEM [][]byte, presentation ErrorPresentation) (map[string]*verifyRecordVault, error) {
	res, err := Prepare(&InputSet{artifacts: []Artifact{a}}, Options{PrivateKeysPEM: privateKeysPEM, Presentation: presentation})
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
			if rv.ecdsaPub == nil {
				rv.ecdsaPub = s.ECDSAPub
			}
		}
		for _, s := range res.SharesEdDSA[vID] {
			if s == nil {
				continue
			}
			rv.algorithms["EdDSA"] = true
			rv.eddsaIDs = append(rv.eddsaIDs, shareIDKey(s.ShareID))
			if rv.eddsaPub == nil {
				rv.eddsaPub = s.EDDSAPub
			}
		}
		out[vID] = rv
	}
	return out, nil
}

// checkVerifyVault fills in the verdict for a vault that at least one decrypted file holds. It
// reports whether the vault's files conflict, plus any reshare-selection warnings.
func checkVerifyVault(vv *VerifyVault, holders []*verifyRecord, decrypted []Artifact, bundles []BundleInfo,
	privateKeysPEM [][]byte, presentation ErrorPresentation) (conflict bool, warnings []Warning) {

	vID := vv.VaultID
	res, err := Prepare(&InputSet{artifacts: decrypted, bundles: bundles},
		Options{VaultID: vID, PrivateKeysPEM: privateKeysPEM, Presentation: presentation, quiet: true})
	if err != nil {
		if errors.Is(err, ErrNotEnoughShares) {
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
		vv.Message = belowThresholdMessage(vv.SharesCounted, vv.Threshold)
	}
	return false, warnings
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
	vv.Message = belowThresholdMessage(vv.SharesCounted, vv.Threshold)
}

func belowThresholdMessage(counted, threshold int) string {
	if threshold < 1 {
		return fmt.Sprintf("%d shares found at the current reshare, which is not enough to recover this vault.", counted)
	}
	missing := threshold - counted
	plural := "s"
	if missing == 1 {
		plural = ""
	}
	return fmt.Sprintf("%d of %d required shares found at the current reshare. Add backups from %d more signer%s.",
		counted, threshold, missing, plural)
}

func notCheckedMessage(holders []*verifyRecord) string {
	for _, rec := range holders {
		if rec.level == VerifyLevelHeader {
			return "Found by file header only. Add the mnemonic or ML-KEM key for its files to check its threshold and shares."
		}
	}
	return "The files that name this vault could not be decrypted."
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

// wipeResultShares zeroes every secret share value a Prepare result holds, once Verify has read
// the identifiers it needs. big.Int does not promise to scrub old backing arrays, so this is best
// effort, like the rest of the tool's key hygiene.
func wipeResultShares(res *Result) {
	if res == nil {
		return
	}
	for _, shares := range res.SharesECDSA {
		for _, s := range shares {
			if s != nil && s.Xi != nil {
				s.Xi.SetInt64(0)
			}
		}
	}
	for _, shares := range res.SharesEdDSA {
		for _, s := range shares {
			if s != nil && s.Xi != nil {
				s.Xi.SetInt64(0)
			}
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
