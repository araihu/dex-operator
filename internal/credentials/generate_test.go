package credentials

import (
	"strings"
	"testing"
	"unicode"

	dexv1alpha1 "github.com/araihu/dex-operator/api/v1alpha1"
	"golang.org/x/crypto/bcrypt"
)

func TestUUID(t *testing.T) {
	if got := LocalUserID("default", "admin"); got != "3f1a2d83-655d-5c4c-864c-ff4b8b83a31e" {
		t.Fatalf("LocalUserID() = %q", got)
	}
	if got := dexNamespaceUUID(); got != "e67d2ae2-f9a7-53db-bdff-875b72f09166" {
		t.Fatalf("dexNamespaceUUID() = %q", got)
	}
}

func TestGeneratePassword(t *testing.T) {
	sets := []dexv1alpha1.PasswordCharacterSet{
		dexv1alpha1.PasswordCharacterSetLetters,
		dexv1alpha1.PasswordCharacterSetNumbers,
		dexv1alpha1.PasswordCharacterSetSymbols,
	}
	allowed := letters + numbers + symbols
	for _, length := range []int{16, 128} {
		password, err := GeneratePassword(length, sets)
		if err != nil {
			t.Fatal(err)
		}
		if len(password) != length {
			t.Fatalf("password length = %d, want %d", len(password), length)
		}
		if !strings.ContainsAny(password, letters) || !strings.ContainsAny(password, numbers) || !strings.ContainsAny(password, symbols) {
			t.Fatalf("password lacks a selected character class")
		}
		for _, character := range password {
			if !strings.ContainsRune(allowed, character) {
				t.Fatalf("password contains disallowed character %q", character)
			}
		}
	}

	for _, length := range []int{15, 129} {
		if _, err := GeneratePassword(length, sets); err == nil {
			t.Fatalf("GeneratePassword(%d) error = nil", length)
		}
	}
	if _, err := GeneratePassword(16, nil); err == nil {
		t.Fatal("GeneratePassword() accepted no character sets")
	}
}

func TestGenerateOAuth2Secret(t *testing.T) {
	secret, err := GenerateOAuth2Secret()
	if err != nil {
		t.Fatal(err)
	}
	if len(secret) != 64 {
		t.Fatalf("secret length = %d, want 64", len(secret))
	}
	for _, character := range secret {
		if !(unicode.IsLetter(character) || unicode.IsDigit(character) || character == '_' || character == '-') || character > unicode.MaxASCII {
			t.Fatalf("secret contains non-URL-safe character %q", character)
		}
	}
}

func TestGenerateBcryptHash(t *testing.T) {
	hash, err := BcryptHash("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	cost, err := bcrypt.Cost(hash)
	if err != nil {
		t.Fatal(err)
	}
	if cost != 12 {
		t.Fatalf("bcrypt cost = %d, want 12", cost)
	}
	if err := bcrypt.CompareHashAndPassword(hash, []byte("correct horse battery staple")); err != nil {
		t.Fatalf("hash verification failed: %v", err)
	}
}
