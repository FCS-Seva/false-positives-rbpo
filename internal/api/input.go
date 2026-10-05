package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"unicode/utf8"
)

func decode(w http.ResponseWriter, r *http.Request, value any) bool {
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/json" {
		failure(w, 400, "expected application/json")
		return false
	}
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 32*1024))
	if err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			failure(w, 413, "request too large")
		} else {
			failure(w, 400, "invalid body")
		}
		return false
	}
	if !utf8.Valid(raw) {
		failure(w, 400, "invalid UTF-8")
		return false
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(value); err != nil {
		failure(w, 400, "invalid JSON or fields")
		return false
	}
	if err := d.Decode(new(any)); err != io.EOF {
		failure(w, 400, "expected one JSON value")
		return false
	}
	return true
}
