//go:build darwin

package process

import (
	"encoding/asn1"
	"encoding/binary"
	"os"
	"reflect"
	"testing"
)

// derTLV builds a single DER tag-length-value using asn1.Marshal of a RawValue.
func derTLV(t *testing.T, tag int, compound bool, content []byte) []byte {
	t.Helper()
	encoded, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        tag,
		IsCompound: compound,
		Bytes:      content,
	})
	if err != nil {
		t.Fatalf("marshal DER tag %d: %v", tag, err)
	}
	return encoded
}

func concat(parts ...[]byte) []byte {
	var out []byte
	for _, part := range parts {
		out = append(out, part...)
	}
	return out
}

func TestParseDEREntitlements(t *testing.T) {
	boolVal := derTLV(t, asn1.TagBoolean, false, []byte{0xff})
	intVal := derTLV(t, asn1.TagInteger, false, []byte{0x2a}) // 42
	strVal := derTLV(t, asn1.TagUTF8String, false, []byte("group.example"))

	// array of two strings -> SEQUENCE OF value
	arrayVal := derTLV(t, asn1.TagSequence, true, concat(
		derTLV(t, asn1.TagUTF8String, false, []byte("a")),
		derTLV(t, asn1.TagUTF8String, false, []byte("b")),
	))

	// nested dictionary -> SET OF entitlement
	nestedDict := derTLV(t, asn1.TagSet, true, derEntry(t,
		"inner", derTLV(t, asn1.TagBoolean, false, []byte{0x00})))

	root := derTLV(t, asn1.TagSet, true, concat(
		derEntry(t, "com.apple.security.app-sandbox", boolVal),
		derEntry(t, "count", intVal),
		derEntry(t, "group", strVal),
		derEntry(t, "list", arrayVal),
		derEntry(t, "nested", nestedDict),
	))

	top := derTLV(t, asn1.TagSequence, true, concat(
		derTLV(t, asn1.TagInteger, false, []byte{0x01}), // version
		root,
	))

	got, err := parseDEREntitlements(top)
	if err != nil {
		t.Fatalf("parseDEREntitlements: %v", err)
	}

	want := map[string]any{
		"com.apple.security.app-sandbox": true,
		"count":                          int64(42),
		"group":                          "group.example",
		"list":                           []any{"a", "b"},
		"nested":                         map[string]any{"inner": false},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("parseDEREntitlements()\n got: %#v\nwant: %#v", got, want)
	}
}

func derEntry(t *testing.T, key string, value []byte) []byte {
	t.Helper()
	return derTLV(t, asn1.TagSequence, true, concat(
		derTLV(t, asn1.TagUTF8String, false, []byte(key)),
		value,
	))
}

func TestBlobTotalLength(t *testing.T) {
	buffer := make([]byte, 32)
	binary.BigEndian.PutUint32(buffer[0:4], csMagicEmbeddedEntitlements)
	binary.BigEndian.PutUint32(buffer[4:8], 20)
	if got := blobTotalLength(buffer); got != 20 {
		t.Fatalf("blobTotalLength() = %d, want 20", got)
	}

	// Wrong magic must not be treated as a blob.
	binary.BigEndian.PutUint32(buffer[0:4], 0xdeadbeef)
	if got := blobTotalLength(buffer); got != 0 {
		t.Fatalf("blobTotalLength(bad magic) = %d, want 0", got)
	}

	// Too short.
	if got := blobTotalLength([]byte{0x00, 0x01}); got != 0 {
		t.Fatalf("blobTotalLength(short) = %d, want 0", got)
	}
}

// TestProcessEntitlementsViaCSOps exercises the csops syscall path directly (the
// exported ProcessEntitlement short-circuits to the current task for our own pid).
func TestProcessEntitlementsViaCSOps(t *testing.T) {
	entitlements, err := processEntitlements(os.Getpid())
	if err != nil {
		t.Skipf("processEntitlements(self) returned no entitlements: %v", err)
	}
	if entitlements == nil {
		t.Fatal("processEntitlements(self) returned nil map without error")
	}
	t.Logf("csops returned %d entitlement keys", len(entitlements))
}
