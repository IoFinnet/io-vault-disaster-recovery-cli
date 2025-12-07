// Copyright (C) 2025 io finnet group, inc.
// SPDX-License-Identifier: AGPL-3.0-or-later
// Full license text available in LICENSE file in repository root.

package hd

import (
	"encoding/csv"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// InputColumns defines the expected input CSV column names
var InputColumns = []string{"address", "xpub", "path", "algorithm", "curve", "flags"}

// OutputColumns defines the output CSV column names
var OutputColumns = []string{"address", "xpub", "path", "algorithm", "curve", "flags", "publickey", "privatekey"}

// ParseCSV reads an input CSV file and returns address records
func ParseCSV(filePath string) ([]AddressRecord, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("addresses file not found: %s", filePath)
	}
	defer file.Close()

	reader := csv.NewReader(file)

	// Read header row
	header, err := reader.Read()
	if err != nil {
		return nil, fmt.Errorf("failed to read CSV header: %w", err)
	}

	// Build column index map (case-insensitive)
	colIndex := make(map[string]int)
	for i, col := range header {
		colIndex[strings.ToLower(strings.TrimSpace(col))] = i
	}

	// Validate required columns exist
	for _, required := range InputColumns {
		if _, ok := colIndex[required]; !ok {
			return nil, fmt.Errorf("%w: %s", ErrCSVMissingColumn, required)
		}
	}

	// Read all records
	rows, err := reader.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("failed to read CSV: %w", err)
	}

	records := make([]AddressRecord, 0, len(rows))
	for rowNum, row := range rows {
		lineNum := rowNum + 2 // +1 for header, +1 for 1-based indexing

		if len(row) < len(InputColumns) {
			return nil, fmt.Errorf("%w at row %d: insufficient columns", ErrCSVInvalidFormat, lineNum)
		}

		// Parse algorithm
		alg, err := ParseAlgorithm(row[colIndex["algorithm"]])
		if err != nil {
			return nil, fmt.Errorf("invalid algorithm at row %d: %s", lineNum, row[colIndex["algorithm"]])
		}

		// Parse curve
		curve, err := ParseCurve(row[colIndex["curve"]])
		if err != nil {
			return nil, fmt.Errorf("invalid curve at row %d: %s", lineNum, row[colIndex["curve"]])
		}

		// Validate algorithm/curve combination
		if err := ValidateAlgorithmCurve(alg, curve); err != nil {
			return nil, fmt.Errorf("unsupported algorithm/curve at row %d: %s/%s", lineNum, alg, curve)
		}

		// Parse flags
		flagsStr := strings.TrimSpace(row[colIndex["flags"]])
		var flags int
		if flagsStr != "" {
			flags, err = strconv.Atoi(flagsStr)
			if err != nil {
				return nil, fmt.Errorf("invalid flags at row %d: %s", lineNum, flagsStr)
			}
		}

		records = append(records, AddressRecord{
			Address:   strings.TrimSpace(row[colIndex["address"]]),
			Xpub:      strings.TrimSpace(row[colIndex["xpub"]]),
			Path:      strings.TrimSpace(row[colIndex["path"]]),
			Algorithm: alg,
			Curve:     curve,
			Flags:     flags,
		})
	}

	return records, nil
}

// WriteCSV writes derived records to the output CSV file
func WriteCSV(filePath string, records []DerivedRecord) error {
	file, err := os.Create(filePath)
	if err != nil {
		return fmt.Errorf("failed to create output CSV: %w", err)
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	// Write header
	if err := writer.Write(OutputColumns); err != nil {
		return fmt.Errorf("failed to write CSV header: %w", err)
	}

	// Write records
	for _, rec := range records {
		row := []string{
			rec.Address,
			rec.Xpub,
			rec.Path,
			string(rec.Algorithm),
			string(rec.Curve),
			strconv.Itoa(rec.Flags),
			rec.PublicKey,
			rec.PrivateKey,
		}
		if err := writer.Write(row); err != nil {
			return fmt.Errorf("failed to write CSV row: %w", err)
		}
	}

	return nil
}

// DeriveOutputPath generates the output file path from input path
// e.g., "input.csv" -> "input_recovered.csv"
func DeriveOutputPath(inputPath string) string {
	ext := filepath.Ext(inputPath)
	base := strings.TrimSuffix(inputPath, ext)
	return base + "_recovered" + ext
}
