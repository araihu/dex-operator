package dex

import (
	"reflect"
	"strings"
	"testing"
)

func TestNormalizeSet(t *testing.T) {
	got := NormalizeSet([]string{"b", "a", "b", "", "a"})
	want := []string{"", "a", "b"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("NormalizeSet() = %#v, want %#v", got, want)
	}
	if got := NormalizeSet(nil); got != nil {
		t.Fatalf("NormalizeSet(nil) = %#v, want nil", got)
	}
}

func TestNormalizeConnectorJSON(t *testing.T) {
	equal, err := ConnectorJSONEqual("default/github", "config.json", []byte(`{"clientID":"id","scopes":["a","b"]}`), []byte("{\n  \"scopes\": [\"a\", \"b\"],\n  \"clientID\": \"id\"\n}"))
	if err != nil || !equal {
		t.Fatalf("ConnectorJSONEqual() = %t, %v, want true, nil", equal, err)
	}

	equal, err = ConnectorJSONEqual("default/github", "config.json", []byte(`{"clientID":"id"}`), []byte(`{"clientID":"other"}`))
	if err != nil || equal {
		t.Fatalf("ConnectorJSONEqual() = %t, %v, want false, nil", equal, err)
	}

	marker := "sentinel-secret-json"
	for _, values := range [][2][]byte{
		{[]byte(`{"secret":"` + marker), []byte(`{}`)},
		{[]byte(`{}`), []byte(`{"secret":"` + marker)},
	} {
		if _, err := ConnectorJSONEqual("default/github", "config.json", values[0], values[1]); err == nil {
			t.Fatal("ConnectorJSONEqual() error = nil, want invalid JSON")
		} else if strings.Contains(err.Error(), marker) {
			t.Fatalf("error exposed connector JSON: %v", err)
		}
	}
}
