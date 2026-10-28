package nobleid

import (
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"testing"
)

// The shared cases in ../../test/profile-vectors.json, which every helper's
// tests also read.
func TestProfileFromClaimsSharedCases(t *testing.T) {
	raw, err := os.ReadFile("../../test/profile-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var file struct {
		Cases []struct {
			Name     string          `json:"name"`
			IDToken  map[string]any  `json:"id_token"`
			Userinfo map[string]any  `json:"userinfo"`
			Profile  json.RawMessage `json:"profile"`
			Error    string          `json:"error"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(raw, &file); err != nil {
		t.Fatal(err)
	}
	for _, c := range file.Cases {
		t.Run(c.Name, func(t *testing.T) {
			got, err := ProfileFromClaims(c.IDToken, c.Userinfo)
			if c.Error != "" {
				var e *Error
				if !errors.As(err, &e) || e.Code != c.Error {
					t.Fatalf("want error %q, got %v", c.Error, err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			// null in the vectors is the zero value here.
			var want Profile
			if err := json.Unmarshal(c.Profile, &want); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(*got, want) {
				g, _ := json.MarshalIndent(got, "", "  ")
				w, _ := json.MarshalIndent(want, "", "  ")
				t.Fatalf("got\n%s\nwant\n%s", g, w)
			}
		})
	}
}

func TestProfileFromClaimsAcceptsNilUserinfo(t *testing.T) {
	p, err := ProfileFromClaims(map[string]any{"sub": "u", "name": " Ada "}, nil)
	if err != nil || p.Name != "Ada" || p.ResearchInterests == nil || p.Affiliations == nil {
		t.Fatalf("%+v %v", p, err)
	}
}
