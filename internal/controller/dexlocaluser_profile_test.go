package controller

import (
	"bytes"
	"encoding/json"
	"slices"
	"testing"

	dexv1alpha1 "github.com/araihu/dex-operator/api/v1alpha1"
	dexapi "github.com/araihu/dex/api/v2"
)

func TestGroupsJSONPresence(t *testing.T) {
	empty := []string{}
	withClear, err := json.Marshal(dexv1alpha1.DexLocalUserSpec{Groups: &empty})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(withClear, []byte(`"groups":[]`)) {
		t.Fatalf("explicit empty groups lost presence: %s", withClear)
	}
	omitted, err := json.Marshal(dexv1alpha1.DexLocalUserSpec{})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(omitted, []byte(`"groups"`)) {
		t.Fatalf("omitted groups gained presence: %s", omitted)
	}
}

func TestNextManagedProfileFieldsIsSticky(t *testing.T) {
	name := "Ada Lovelace"
	resource := &dexv1alpha1.DexLocalUser{
		Spec: dexv1alpha1.DexLocalUserSpec{
			Name:   &name,
			Groups: &[]string{},
		},
		Status: dexv1alpha1.DexLocalUserStatus{
			ManagedProfileFields: []dexv1alpha1.DexLocalUserProfileField{
				dexv1alpha1.DexLocalUserProfileFieldPreferredUsername,
			},
		},
	}

	want := []dexv1alpha1.DexLocalUserProfileField{
		dexv1alpha1.DexLocalUserProfileFieldName,
		dexv1alpha1.DexLocalUserProfileFieldPreferredUsername,
		dexv1alpha1.DexLocalUserProfileFieldGroups,
	}
	if got := nextManagedProfileFields(resource); !slices.Equal(got, want) {
		t.Fatalf("nextManagedProfileFields() = %#v, want %#v", got, want)
	}
}

func TestUnmanagedProfilePreservesObservedValues(t *testing.T) {
	verified := true
	resource := &dexv1alpha1.DexLocalUser{}
	observed := &dexapi.Password{
		Name:              "Existing Name",
		PreferredUsername: "existing",
		EmailVerified:     &verified,
		Groups:            []string{"existing-group"},
	}
	request := &dexapi.UpdatePasswordReq{}

	if applyManagedProfileUpdate(resource, observed, request) {
		t.Fatalf("unmanaged profile planned an update: %#v", request)
	}
}

func TestManagedProfilePlansValuesAndClear(t *testing.T) {
	name := "Ada Lovelace"
	preferredUsername := "ada"
	emailVerified := true
	resource := &dexv1alpha1.DexLocalUser{
		Spec: dexv1alpha1.DexLocalUserSpec{
			Name:              &name,
			PreferredUsername: &preferredUsername,
			EmailVerified:     &emailVerified,
			Groups:            &[]string{"operators", "developers"},
		},
		Status: dexv1alpha1.DexLocalUserStatus{ManagedProfileFields: allLocalUserProfileFields},
	}
	observedVerified := false
	observed := &dexapi.Password{
		Name:              "Drifted",
		PreferredUsername: "drifted",
		EmailVerified:     &observedVerified,
		Groups:            []string{"drifted"},
	}
	request := &dexapi.UpdatePasswordReq{}

	if !applyManagedProfileUpdate(resource, observed, request) {
		t.Fatal("managed drift did not plan an update")
	}
	if request.NewName == nil || *request.NewName != name || request.NewPreferredUsername == nil || *request.NewPreferredUsername != preferredUsername {
		t.Fatalf("string profile update = %#v", request)
	}
	if request.NewEmailVerified == nil || !*request.NewEmailVerified {
		t.Fatalf("emailVerified update = %#v", request.NewEmailVerified)
	}
	if request.NewGroups == nil || !slices.Equal(request.NewGroups.Groups, desiredProfileGroups(resource.Spec.Groups)) {
		t.Fatalf("groups update = %#v", request.NewGroups)
	}

	empty := ""
	cleared := false
	resource.Spec.Name = &empty
	resource.Spec.PreferredUsername = &empty
	resource.Spec.EmailVerified = &cleared
	resource.Spec.Groups = &[]string{}
	request = &dexapi.UpdatePasswordReq{}
	if !applyManagedProfileUpdate(resource, &dexapi.Password{
		Name:              name,
		PreferredUsername: preferredUsername,
		EmailVerified:     &emailVerified,
		Groups:            []string{"developers"},
	}, request) {
		t.Fatal("explicit zero values did not plan a clear")
	}
	assertClearProfileRequest(t, request)
}

func TestRemovedManagedProfileFieldsRemainOwnedAndClear(t *testing.T) {
	verified := true
	resource := &dexv1alpha1.DexLocalUser{
		Status: dexv1alpha1.DexLocalUserStatus{ManagedProfileFields: allLocalUserProfileFields},
	}
	request := &dexapi.UpdatePasswordReq{}
	if !applyManagedProfileUpdate(resource, &dexapi.Password{
		Name:              "Previously Managed",
		PreferredUsername: "managed",
		EmailVerified:     &verified,
		Groups:            []string{"managed"},
	}, request) {
		t.Fatal("removed managed fields did not plan a clear")
	}
	assertClearProfileRequest(t, request)

	convergedVerified := false
	converged := &dexapi.Password{EmailVerified: &convergedVerified, Groups: []string{}}
	if applyManagedProfileUpdate(resource, converged, &dexapi.UpdatePasswordReq{}) {
		t.Fatal("cleared managed profile did not converge")
	}
}

func TestApplyManagedProfileToCreatePassword(t *testing.T) {
	name := "Grace Hopper"
	preferredUsername := "grace"
	verified := false
	resource := &dexv1alpha1.DexLocalUser{
		Spec: dexv1alpha1.DexLocalUserSpec{
			Name:              &name,
			PreferredUsername: &preferredUsername,
			EmailVerified:     &verified,
			Groups:            &[]string{},
		},
		Status: dexv1alpha1.DexLocalUserStatus{ManagedProfileFields: allLocalUserProfileFields},
	}
	password := &dexapi.Password{}

	applyManagedProfileToPassword(resource, password)
	if password.Name != name || password.PreferredUsername != preferredUsername {
		t.Fatalf("created string profile = %#v", password)
	}
	if password.EmailVerified == nil || *password.EmailVerified {
		t.Fatalf("created emailVerified = %#v", password.EmailVerified)
	}
	if password.Groups == nil || len(password.Groups) != 0 {
		t.Fatalf("created groups = %#v, want explicit empty list", password.Groups)
	}
}

func assertClearProfileRequest(t *testing.T, request *dexapi.UpdatePasswordReq) {
	t.Helper()
	if request.NewName == nil || *request.NewName != "" || request.NewPreferredUsername == nil || *request.NewPreferredUsername != "" {
		t.Fatalf("string clear = %#v", request)
	}
	if request.NewEmailVerified == nil || *request.NewEmailVerified {
		t.Fatalf("emailVerified clear = %#v", request.NewEmailVerified)
	}
	if request.NewGroups == nil || request.NewGroups.Groups == nil || len(request.NewGroups.Groups) != 0 {
		t.Fatalf("groups clear = %#v", request.NewGroups)
	}
}
