//go:build darwin

package process

import (
	"encoding/binary"
	"fmt"
	"math"
	"unsafe"

	purego "github.com/ebitengine/purego"
	howettplist "howett.net/plist"

	"github.com/deploymenttheory/go-macos-sandbox/entitlements"
)

const (
	// csops(2) operation codes for reading a process's entitlements. The DER blob
	// is the format the kernel prefers on modern macOS; the legacy blob is an XML
	// property list kept for older systems.
	csOpsEntitlementsBlob    = 7
	csOpsDerEntitlementsBlob = 16

	// Initial read buffer. Entitlement sets are small, but csops tells us the real
	// size when this is too small, so we retry with the requested length.
	entitlementsBlobBufferSize = 65536
	maxEntitlementsBlobSize    = 16 << 20 // 16 MiB ceiling for a retry, defensive

	// Code-signature blobs start with an 8-byte big-endian header: a magic number
	// and the total blob length (header included). See xnu cs_blobs.h.
	csBlobHeaderSize = 8

	// Magic numbers identifying the two entitlement blob encodings.
	csMagicEmbeddedEntitlements    = 0xfade7171 // XML property list payload
	csMagicEmbeddedDerEntitlements = 0xfade7172 // DER (ASN.1) payload
)

var fnCsops func(int32, uint32, unsafe.Pointer, uintptr) int32

func init() {
	purego.RegisterLibFunc(&fnCsops, purego.RTLD_DEFAULT, "csops")
}

// processEntitlements returns the runtime entitlements for pid by reading the
// code-signing entitlement blob via csops(2). The DER blob is tried first because
// it is the format the kernel maintains on current macOS; the legacy XML blob is
// the fallback for processes (or systems) that only expose it.
func processEntitlements(pid int) (map[string]any, error) {
	if pid <= 0 {
		return nil, fmt.Errorf("%w: %d", ErrInvalidPID, pid)
	}

	for _, operation := range []uint32{csOpsDerEntitlementsBlob, csOpsEntitlementsBlob} {
		ents, err := entitlementsFromCSOps(pid, operation)
		if err == nil {
			return ents, nil
		}
	}
	return nil, entitlements.ErrEntitlementNotFound
}

func entitlementsFromCSOps(pid int, operation uint32) (map[string]any, error) {
	payload, err := readEntitlementsBlob(pid, operation)
	if err != nil {
		return nil, err
	}

	var root any
	switch operation {
	case csOpsDerEntitlementsBlob:
		dict, err := parseDEREntitlements(payload)
		if err != nil {
			return nil, fmt.Errorf("decode DER process entitlements: %w", err)
		}
		return dict, nil
	default:
		if _, err := howettplist.Unmarshal(payload, &root); err != nil {
			return nil, fmt.Errorf("decode process entitlements: %w", err)
		}
	}

	dict, ok := root.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%w: not a dictionary", entitlements.ErrMalformedEntitlements)
	}
	return dict, nil
}

// readEntitlementsBlob issues csops for the given operation and returns the blob
// payload with the 8-byte header stripped. When the initial buffer is too small,
// the kernel reports the required length in the header and we retry once.
func readEntitlementsBlob(pid int, operation uint32) ([]byte, error) {
	if fnCsops == nil {
		return nil, fmt.Errorf("%w: symbol unavailable", ErrCSOps)
	}
	if pid <= 0 || pid > math.MaxInt32 {
		return nil, fmt.Errorf("%w: %d", ErrInvalidPID, pid)
	}

	size := entitlementsBlobBufferSize
	for range 2 {
		buffer := make([]byte, size)
		ret := fnCsops(int32(pid), operation, unsafe.Pointer(&buffer[0]), uintptr(len(buffer)))

		// Even on failure the kernel may have written the blob header reporting the
		// length it needs. Use it to decide whether a larger retry can succeed.
		total := blobTotalLength(buffer)
		if ret != 0 {
			if total > len(buffer) && total <= maxEntitlementsBlobSize {
				size = total
				continue
			}
			return nil, fmt.Errorf("%w: pid %d", ErrCSOps, pid)
		}

		if total <= csBlobHeaderSize || total > len(buffer) {
			return nil, entitlements.ErrEntitlementNotFound
		}
		return buffer[csBlobHeaderSize:total], nil
	}
	return nil, fmt.Errorf("%w: blob for pid %d exceeds buffer", ErrCSOps, pid)
}

// blobTotalLength reads the big-endian total length from a code-signature blob
// header, validating the magic identifies an entitlements blob. It returns 0 when
// the buffer is too short or the magic is unrecognized.
func blobTotalLength(buffer []byte) int {
	if len(buffer) < csBlobHeaderSize {
		return 0
	}
	magic := binary.BigEndian.Uint32(buffer[0:4])
	if magic != csMagicEmbeddedEntitlements && magic != csMagicEmbeddedDerEntitlements {
		return 0
	}
	return int(binary.BigEndian.Uint32(buffer[4:8]))
}
