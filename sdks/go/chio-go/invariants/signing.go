package invariants

import (
	"crypto/ed25519"
	"encoding/hex"
	"strings"
)

type SignedMessage struct {
	CanonicalJSON string
	PublicKeyHex  string
	SignatureHex  string
}

func IsValidEd25519PublicKeyHex(value string) bool {
	_, err := decodeFixedHex(value, 32, "invalid_public_key")
	return err == nil
}

func IsValidEd25519SignatureHex(value string) bool {
	_, err := decodeFixedHex(value, 64, "invalid_signature")
	return err == nil
}

func PublicKeyHexMatches(left string, right string) bool {
	return normalizeHex(left) == normalizeHex(right)
}

func SignUTF8MessageEd25519(input string, seedHex string) (SignedMessage, error) {
	seed, err := decodeFixedHex(seedHex, 32, "invalid_hex")
	if err != nil {
		return SignedMessage{}, err
	}
	privateKey := ed25519.NewKeyFromSeed(seed)
	publicKey := privateKey.Public().(ed25519.PublicKey)
	signature := ed25519.Sign(privateKey, []byte(input))
	return SignedMessage{
		PublicKeyHex: hex.EncodeToString(publicKey),
		SignatureHex: hex.EncodeToString(signature),
	}, nil
}

func VerifyUTF8MessageEd25519(input string, publicKeyHex string, signatureHex string) (bool, error) {
	publicKey, err := decodeFixedHex(publicKeyHex, 32, "invalid_public_key")
	if err != nil {
		return false, err
	}
	signature, err := decodeFixedHex(signatureHex, 64, "invalid_signature")
	if err != nil {
		return false, err
	}
	return ed25519.Verify(ed25519.PublicKey(publicKey), []byte(input), signature), nil
}

func SignJSONStringEd25519(input string, seedHex string) (SignedMessage, error) {
	canonicalJSON, err := CanonicalizeJSONString(input)
	if err != nil {
		return SignedMessage{}, err
	}
	signed, err := SignUTF8MessageEd25519(canonicalJSON, seedHex)
	if err != nil {
		return SignedMessage{}, err
	}
	signed.CanonicalJSON = canonicalJSON
	return signed, nil
}

func VerifyJSONStringSignatureEd25519(input string, publicKeyHex string, signatureHex string) (bool, error) {
	canonicalJSON, err := CanonicalizeJSONString(input)
	if err != nil {
		return false, err
	}
	return VerifyUTF8MessageEd25519(canonicalJSON, publicKeyHex, signatureHex)
}

func normalizeHex(value string) string {
	normalized := strings.TrimPrefix(strings.TrimPrefix(value, "0x"), "0X")
	return strings.ToLower(normalized)
}

func decodeFixedHex(value string, expectedBytes int, code string) ([]byte, error) {
	normalized := normalizeHex(value)
	if len(normalized) != expectedBytes*2 {
		return nil, newInvariantError(code, "value has an unexpected hexadecimal length")
	}
	decoded, err := hex.DecodeString(normalized)
	if err != nil {
		return nil, newInvariantError(code, "value is not valid hexadecimal")
	}
	return decoded, nil
}
