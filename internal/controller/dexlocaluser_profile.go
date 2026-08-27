package controller

import (
	"slices"

	dexv1alpha1 "github.com/araihu/dex-operator/api/v1alpha1"
	dexclient "github.com/araihu/dex-operator/internal/dex"
	dexapi "github.com/araihu/dex/api/v2"
)

var allLocalUserProfileFields = []dexv1alpha1.DexLocalUserProfileField{
	dexv1alpha1.DexLocalUserProfileFieldName,
	dexv1alpha1.DexLocalUserProfileFieldPreferredUsername,
	dexv1alpha1.DexLocalUserProfileFieldEmailVerified,
	dexv1alpha1.DexLocalUserProfileFieldGroups,
}

func nextManagedProfileFields(resource *dexv1alpha1.DexLocalUser) []dexv1alpha1.DexLocalUserProfileField {
	managed := make([]dexv1alpha1.DexLocalUserProfileField, 0, len(allLocalUserProfileFields))
	for _, field := range allLocalUserProfileFields {
		if slices.Contains(resource.Status.ManagedProfileFields, field) || profileFieldDeclared(resource, field) {
			managed = append(managed, field)
		}
	}
	return managed
}

func profileFieldDeclared(resource *dexv1alpha1.DexLocalUser, field dexv1alpha1.DexLocalUserProfileField) bool {
	switch field {
	case dexv1alpha1.DexLocalUserProfileFieldName:
		return resource.Spec.Name != nil
	case dexv1alpha1.DexLocalUserProfileFieldPreferredUsername:
		return resource.Spec.PreferredUsername != nil
	case dexv1alpha1.DexLocalUserProfileFieldEmailVerified:
		return resource.Spec.EmailVerified != nil
	case dexv1alpha1.DexLocalUserProfileFieldGroups:
		return resource.Spec.Groups != nil
	default:
		return false
	}
}

func profileFieldManaged(resource *dexv1alpha1.DexLocalUser, field dexv1alpha1.DexLocalUserProfileField) bool {
	return slices.Contains(resource.Status.ManagedProfileFields, field)
}

func applyManagedProfileToPassword(resource *dexv1alpha1.DexLocalUser, password *dexapi.Password) {
	if profileFieldManaged(resource, dexv1alpha1.DexLocalUserProfileFieldName) {
		password.Name = stringValue(resource.Spec.Name)
	}
	if profileFieldManaged(resource, dexv1alpha1.DexLocalUserProfileFieldPreferredUsername) {
		password.PreferredUsername = stringValue(resource.Spec.PreferredUsername)
	}
	if profileFieldManaged(resource, dexv1alpha1.DexLocalUserProfileFieldEmailVerified) {
		value := boolValue(resource.Spec.EmailVerified)
		password.EmailVerified = &value
	}
	if profileFieldManaged(resource, dexv1alpha1.DexLocalUserProfileFieldGroups) {
		password.Groups = desiredProfileGroups(resource.Spec.Groups)
	}
}

func applyManagedProfileUpdate(resource *dexv1alpha1.DexLocalUser, observed *dexapi.Password, request *dexapi.UpdatePasswordReq) bool {
	changed := false
	if profileFieldManaged(resource, dexv1alpha1.DexLocalUserProfileFieldName) {
		desired := stringValue(resource.Spec.Name)
		if observed.GetName() != desired {
			request.NewName = &desired
			changed = true
		}
	}
	if profileFieldManaged(resource, dexv1alpha1.DexLocalUserProfileFieldPreferredUsername) {
		desired := stringValue(resource.Spec.PreferredUsername)
		if observed.GetPreferredUsername() != desired {
			request.NewPreferredUsername = &desired
			changed = true
		}
	}
	if profileFieldManaged(resource, dexv1alpha1.DexLocalUserProfileFieldEmailVerified) {
		desired := boolValue(resource.Spec.EmailVerified)
		if observed.EmailVerified == nil || observed.GetEmailVerified() != desired {
			request.NewEmailVerified = &desired
			changed = true
		}
	}
	if profileFieldManaged(resource, dexv1alpha1.DexLocalUserProfileFieldGroups) {
		desired := desiredProfileGroups(resource.Spec.Groups)
		if !slices.Equal(dexclient.NormalizeSet(observed.GetGroups()), desired) {
			request.NewGroups = &dexapi.PasswordGroups{Groups: desired}
			changed = true
		}
	}
	return changed
}

func stringValue(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

func boolValue(value *bool) bool {
	return value != nil && *value
}

func desiredProfileGroups(groups *[]string) []string {
	var values []string
	if groups != nil {
		values = *groups
	}
	normalized := dexclient.NormalizeSet(values)
	if normalized == nil {
		return []string{}
	}
	return normalized
}
