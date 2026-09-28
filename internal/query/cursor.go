package query

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

type cursorPayload struct {
	Version    int    `json:"v"`
	ReceivedAt string `json:"received_at"`
	ReceiptID  string `json:"receipt_id"`
	RevisionID string `json:"revision_id"`
}

func EncodeCursor(cursor EventCursor) (string, error) {
	if err := validateCursor(cursor); err != nil {
		return "", err
	}
	body, err := json.Marshal(cursorPayload{
		Version: 1, ReceivedAt: cursor.ReceivedAt.UTC().Format(time.RFC3339Nano),
		ReceiptID: cursor.ReceiptID, RevisionID: cursor.RevisionID,
	})
	if err != nil {
		return "", fmt.Errorf("encode cursor: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(body), nil
}

func DecodeCursor(encoded string) (EventCursor, error) {
	if encoded == "" || len(encoded) > MaxCursorBytes {
		return EventCursor{}, errors.New("cursor is empty or too large")
	}
	body, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || len(body) > MaxCursorBytes {
		return EventCursor{}, errors.New("cursor is not valid base64url")
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	var payload cursorPayload
	if err := decoder.Decode(&payload); err != nil {
		return EventCursor{}, errors.New("cursor payload is invalid")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return EventCursor{}, errors.New("cursor contains trailing data")
	}
	if payload.Version != 1 {
		return EventCursor{}, errors.New("cursor version is unsupported")
	}
	receivedAt, err := time.Parse(time.RFC3339Nano, payload.ReceivedAt)
	if err != nil {
		return EventCursor{}, errors.New("cursor received_at is invalid")
	}
	cursor := EventCursor{ReceivedAt: receivedAt.UTC(), ReceiptID: payload.ReceiptID, RevisionID: payload.RevisionID}
	if err := validateCursor(cursor); err != nil {
		return EventCursor{}, err
	}
	return cursor, nil
}

func validateCursor(cursor EventCursor) error {
	if cursor.ReceivedAt.IsZero() || !validID(cursor.ReceiptID) || !validID(cursor.RevisionID) {
		return errors.New("cursor identity is invalid")
	}
	return nil
}

func validID(value string) bool {
	if len(value) == 0 || len(value) > 128 {
		return false
	}
	for index, character := range value {
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || index > 0 && strings.ContainsRune("._:-", character) {
			continue
		}
		return false
	}
	return true
}
