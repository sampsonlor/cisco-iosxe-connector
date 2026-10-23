package provider

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"unicode/utf8"
)

var errJSON = errors.New("invalid JSON")

// Decode through tokens so duplicate object keys cannot be silently replaced
// by either encoding/json or an SDK-generated UnmarshalJSON method.
func strictJSON(raw []byte) (any, error) {
	if !utf8.Valid(raw) {
		return nil, errJSON
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	v, err := jsonValue(d, 0)
	if err != nil {
		return nil, err
	}
	if _, err = d.Token(); err != io.EOF {
		return nil, errJSON
	}
	return v, nil
}

func jsonValue(d *json.Decoder, depth int) (any, error) {
	if depth > 16 {
		return nil, errJSON
	}
	token, err := d.Token()
	if err != nil {
		return nil, err
	}
	delim, composite := token.(json.Delim)
	if !composite {
		return token, nil
	}
	switch delim {
	case '{':
		m := make(map[string]any)
		for d.More() {
			key, err := d.Token()
			if err != nil {
				return nil, err
			}
			name, ok := key.(string)
			if !ok {
				return nil, errJSON
			}
			if _, exists := m[name]; exists {
				return nil, errJSON
			}
			value, err := jsonValue(d, depth+1)
			if err != nil {
				return nil, err
			}
			m[name] = value
		}
		if end, err := d.Token(); err != nil || end != json.Delim('}') {
			return nil, errJSON
		}
		return m, nil
	case '[':
		a := make([]any, 0)
		for d.More() {
			value, err := jsonValue(d, depth+1)
			if err != nil {
				return nil, err
			}
			a = append(a, value)
		}
		if end, err := d.Token(); err != nil || end != json.Delim(']') {
			return nil, errJSON
		}
		return a, nil
	default:
		return nil, errJSON
	}
}

func object(value any, required []string, optional ...string) (map[string]any, bool) {
	m, ok := value.(map[string]any)
	if !ok {
		return nil, false
	}
	allowed := make(map[string]bool, len(required)+len(optional))
	for _, key := range required {
		if v, exists := m[key]; !exists || v == nil {
			return nil, false
		}
		allowed[key] = true
	}
	for _, key := range optional {
		allowed[key] = true
	}
	for key, value := range m {
		if !allowed[key] || value == nil {
			return nil, false
		}
	}
	return m, true
}
