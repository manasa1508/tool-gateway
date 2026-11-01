package audit

import (
	"bytes"
	"encoding/json"

	"github.com/manasa1508/tool-gateway/internal/wire"
)

func decodeEntry(m map[string]any, e *Entry) error {
	d := json.NewDecoder(bytes.NewReader(wire.Canonical(m)))
	d.DisallowUnknownFields()
	return d.Decode(e)
}
