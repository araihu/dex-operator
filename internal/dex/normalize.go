package dex

import (
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
)

// NormalizeSet returns a sorted, duplicate-free copy of a set-like list.
func NormalizeSet(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	unique := make(map[string]struct{}, len(values))
	for _, value := range values {
		unique[value] = struct{}{}
	}
	normalized := make([]string, 0, len(unique))
	for value := range unique {
		normalized = append(normalized, value)
	}
	sort.Strings(normalized)
	return normalized
}

// ConnectorJSONEqual compares connector configuration semantically without formatting its bytes.
func ConnectorJSONEqual(resource, secretKey string, desired, observed []byte) (bool, error) {
	var desiredValue, observedValue any
	if err := json.Unmarshal(desired, &desiredValue); err != nil {
		return false, fmt.Errorf("invalid connector JSON for %s Secret key %q", resource, secretKey)
	}
	if err := json.Unmarshal(observed, &observedValue); err != nil {
		return false, fmt.Errorf("invalid observed connector JSON for %s", resource)
	}
	return reflect.DeepEqual(desiredValue, observedValue), nil
}
