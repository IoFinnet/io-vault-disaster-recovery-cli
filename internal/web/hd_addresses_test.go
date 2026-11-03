// Copyright (C) 2025 io finnet group, inc.
// SPDX-License-Identifier: AGPL-3.0-or-later
// Full license text available in LICENSE file in repository root.

package web

import (
	"bytes"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/IoFinnet/io-vault-disaster-recovery-cli/internal/hd"
	"github.com/stretchr/testify/require"
)

func TestProcessHDAddresses_XpubNotMatchingMasterKey(t *testing.T) {
	var body bytes.Buffer
	form := multipart.NewWriter(&body)
	part, err := form.CreateFormFile("hdAddressesCSV", "addresses.csv")
	require.NoError(t, err)
	_, err = part.Write([]byte("address,xpub,path,algorithm,curve,flags\n" +
		"addr1,xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8,m/0,ECDSA,secp256k1,0\n"))
	require.NoError(t, err)
	require.NoError(t, form.Close())

	req := httptest.NewRequest(http.MethodPost, "/api/recover", &body)
	req.Header.Set("Content-Type", form.FormDataContentType())
	require.NoError(t, req.ParseMultipartForm(1<<20))

	wrongSK := make([]byte, 32)
	wrongSK[31] = 1

	addresses, err := (&Server{}).processHDAddresses(req, wrongSK, nil)

	require.ErrorIs(t, err, hd.ErrXpubKeyMismatch)
	require.Empty(t, addresses)
}
