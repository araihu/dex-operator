package credentials

import (
	"crypto/rand"
	"crypto/sha1" // UUIDv5 requires SHA-1 by specification.
	"encoding/hex"
	"fmt"
	"math/big"

	dexv1alpha1 "github.com/araihu/dex-operator/api/v1alpha1"
	"golang.org/x/crypto/bcrypt"
)

const (
	letters          = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	numbers          = "0123456789"
	symbols          = "!@#$%^&*()-_=+[]{}:,.?"
	oauth2Characters = letters + numbers + "_-"
	bcryptCost       = 12
)

var dnsNamespace = [16]byte{0x6b, 0xa7, 0xb8, 0x10, 0x9d, 0xad, 0x11, 0xd1, 0x80, 0xb4, 0x00, 0xc0, 0x4f, 0xd4, 0x30, 0xc8}

// LocalUserID derives the stable Dex local-user subject for one Kubernetes object.
func LocalUserID(namespace, name string) string {
	dexNamespace := uuidV5(dnsNamespace, "dex.araihu.com")
	return formatUUID(uuidV5(dexNamespace, "DexLocalUser/"+namespace+"/"+name))
}

func dexNamespaceUUID() string {
	return formatUUID(uuidV5(dnsNamespace, "dex.araihu.com"))
}

func uuidV5(namespace [16]byte, name string) [16]byte {
	hash := sha1.New()
	_, _ = hash.Write(namespace[:])
	_, _ = hash.Write([]byte(name))
	var uuid [16]byte
	copy(uuid[:], hash.Sum(nil))
	uuid[6] = (uuid[6] & 0x0f) | 0x50
	uuid[8] = (uuid[8] & 0x3f) | 0x80
	return uuid
}

func formatUUID(uuid [16]byte) string {
	encoded := make([]byte, 36)
	hex.Encode(encoded[0:8], uuid[0:4])
	encoded[8] = '-'
	hex.Encode(encoded[9:13], uuid[4:6])
	encoded[13] = '-'
	hex.Encode(encoded[14:18], uuid[6:8])
	encoded[18] = '-'
	hex.Encode(encoded[19:23], uuid[8:10])
	encoded[23] = '-'
	hex.Encode(encoded[24:36], uuid[10:16])
	return string(encoded)
}

// GeneratePassword returns a cryptographically random password matching the selected policy.
func GeneratePassword(length int, selected []dexv1alpha1.PasswordCharacterSet) (string, error) {
	if length < 16 || length > 128 {
		return "", fmt.Errorf("password length must be between 16 and 128")
	}
	classes, err := characterClasses(selected)
	if err != nil {
		return "", err
	}
	characters := make([]byte, 0, length)
	allowed := ""
	for _, class := range classes {
		character, err := randomCharacter(class)
		if err != nil {
			return "", err
		}
		characters = append(characters, character)
		allowed += class
	}
	for len(characters) < length {
		character, err := randomCharacter(allowed)
		if err != nil {
			return "", err
		}
		characters = append(characters, character)
	}
	if err := shuffle(characters); err != nil {
		return "", err
	}
	return string(characters), nil
}

// GenerateOAuth2Secret returns a 64-character URL-safe client secret.
func GenerateOAuth2Secret() (string, error) {
	characters := make([]byte, 64)
	for index := range characters {
		character, err := randomCharacter(oauth2Characters)
		if err != nil {
			return "", err
		}
		characters[index] = character
	}
	return string(characters), nil
}

// BcryptHash hashes a password at the operator's fixed cost.
func BcryptHash(password string) ([]byte, error) {
	return bcrypt.GenerateFromPassword([]byte(password), bcryptCost)
}

func characterClasses(selected []dexv1alpha1.PasswordCharacterSet) ([]string, error) {
	seen := make(map[dexv1alpha1.PasswordCharacterSet]bool, len(selected))
	classes := make([]string, 0, len(selected))
	for _, selection := range selected {
		if seen[selection] {
			continue
		}
		seen[selection] = true
		switch selection {
		case dexv1alpha1.PasswordCharacterSetLetters:
			classes = append(classes, letters)
		case dexv1alpha1.PasswordCharacterSetNumbers:
			classes = append(classes, numbers)
		case dexv1alpha1.PasswordCharacterSetSymbols:
			classes = append(classes, symbols)
		default:
			return nil, fmt.Errorf("unsupported password character set")
		}
	}
	if len(classes) == 0 {
		return nil, fmt.Errorf("at least one password character set is required")
	}
	return classes, nil
}

func randomCharacter(characters string) (byte, error) {
	index, err := rand.Int(rand.Reader, big.NewInt(int64(len(characters))))
	if err != nil {
		return 0, fmt.Errorf("read cryptographic randomness: %w", err)
	}
	return characters[index.Int64()], nil
}

func shuffle(characters []byte) error {
	for index := len(characters) - 1; index > 0; index-- {
		other, err := rand.Int(rand.Reader, big.NewInt(int64(index+1)))
		if err != nil {
			return fmt.Errorf("read cryptographic randomness: %w", err)
		}
		characters[index], characters[other.Int64()] = characters[other.Int64()], characters[index]
	}
	return nil
}
