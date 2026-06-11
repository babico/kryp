package crypto

import (
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	MetadataFlagName byte = 1 << iota
	MetadataFlagPath
)

var MagicBytes = [4]byte{'E', 'N', 'C', 'R'}

type Header struct {
	Version      byte
	Algorithm    AlgorithmID
	KDFMethod    KDFMethod
	KDFSalt      []byte
	KDFParams    []byte
	Nonce        []byte
	OriginalName string
	OriginalPath string
}

func encodeMetadata(name, path string) []byte {
	var buf []byte
	var flags byte
	if name != "" {
		flags |= MetadataFlagName
	}
	if path != "" {
		flags |= MetadataFlagPath
	}
	buf = append(buf, flags)

	if name != "" {
		n := uint16(len(name))
		buf = append(buf, byte(n>>8), byte(n))
		buf = append(buf, []byte(name)...)
	}
	if path != "" {
		p := uint16(len(path))
		buf = append(buf, byte(p>>8), byte(p))
		buf = append(buf, []byte(path)...)
	}
	return buf
}

func decodeMetadata(data []byte) (name, path string, consumed int) {
	if len(data) == 0 {
		return "", "", 0
	}
	flags := data[0]
	off := 1

	if flags&MetadataFlagName != 0 {
		if off+2 > len(data) {
			return name, path, off
		}
		nlen := int(binary.BigEndian.Uint16(data[off : off+2]))
		off += 2
		if off+nlen > len(data) {
			return name, path, off
		}
		name = string(data[off : off+nlen])
		off += nlen
	}

	if flags&MetadataFlagPath != 0 {
		if off+2 > len(data) {
			return name, path, off
		}
		plen := int(binary.BigEndian.Uint16(data[off : off+2]))
		off += 2
		if off+plen > len(data) {
			return name, path, off
		}
		path = string(data[off : off+plen])
		off += plen
	}

	return name, path, off
}

func (h *Header) Encode() []byte {
	hasKDF := byte(0)
	var kdfData []byte
	if h.KDFMethod != KDFNone {
		hasKDF = 1
		kdfData = append(kdfData, byte(h.KDFMethod))
		saltLen := uint16(len(h.KDFSalt))
		sl := make([]byte, 2)
		binary.BigEndian.PutUint16(sl, saltLen)
		kdfData = append(kdfData, sl...)
		kdfData = append(kdfData, h.KDFSalt...)
		paramLen := uint16(len(h.KDFParams))
		pl := make([]byte, 2)
		binary.BigEndian.PutUint16(pl, paramLen)
		kdfData = append(kdfData, pl...)
		kdfData = append(kdfData, h.KDFParams...)
	}

	hasMetadata := byte(0)
	var metadataData []byte
	if h.OriginalName != "" || h.OriginalPath != "" {
		hasMetadata = 1
		metadataData = encodeMetadata(h.OriginalName, h.OriginalPath)
	}

	algoData := append([]byte{byte(h.Algorithm)}, h.Nonce...)

	body := append([]byte{hasKDF}, kdfData...)
	body = append(body, hasMetadata)
	body = append(body, metadataData...)
	body = append(body, algoData...)
	bodyLen := uint32(len(body))

	buf := make([]byte, 4+1+4+len(body))
	copy(buf[0:4], MagicBytes[:])
	buf[4] = h.Version
	binary.BigEndian.PutUint32(buf[5:9], bodyLen)
	copy(buf[9:], body)

	return buf
}

func DecodeHeader(data []byte) (*Header, error) {
	if len(data) < 9 {
		return nil, errors.New("data too short for header")
	}

	if data[0] != 'E' || data[1] != 'N' || data[2] != 'C' || data[3] != 'R' {
		return nil, errors.New("invalid magic bytes")
	}

	version := data[4]
	if version != 1 {
		return nil, fmt.Errorf("unsupported header version: %d", version)
	}

	bodyLen := binary.BigEndian.Uint32(data[5:9])
	if uint32(len(data)) < 9+bodyLen {
		return nil, errors.New("data too short for header body")
	}

	body := data[9 : 9+bodyLen]
	offset := 0

	h := &Header{Version: version}

	if offset >= len(body) {
		return nil, errors.New("empty header body")
	}

	hasKDF := body[offset]
	offset++

	if hasKDF == 1 {
		if offset+1 > len(body) {
			return nil, errors.New("truncated KDF method")
		}
		h.KDFMethod = KDFMethod(body[offset])
		offset++

		if offset+2 > len(body) {
			return nil, errors.New("truncated KDF salt length")
		}
		saltLen := int(binary.BigEndian.Uint16(body[offset : offset+2]))
		offset += 2

		if offset+saltLen > len(body) {
			return nil, errors.New("truncated KDF salt")
		}
		h.KDFSalt = make([]byte, saltLen)
		copy(h.KDFSalt, body[offset:offset+saltLen])
		offset += saltLen

		if offset+2 > len(body) {
			return nil, errors.New("truncated KDF param length")
		}
		paramLen := int(binary.BigEndian.Uint16(body[offset : offset+2]))
		offset += 2

		if offset+paramLen > len(body) {
			return nil, errors.New("truncated KDF params")
		}
		h.KDFParams = make([]byte, paramLen)
		copy(h.KDFParams, body[offset:offset+paramLen])
		offset += paramLen
	}

	if offset >= len(body) {
		return nil, errors.New("missing hasMetadata")
	}
	hasMetadata := body[offset]
	offset++

	if hasMetadata == 1 {
		name, path, consumed := decodeMetadata(body[offset:])
		h.OriginalName = name
		h.OriginalPath = path
		offset += consumed
		if consumed == 0 {
			return nil, errors.New("truncated metadata")
		}
	}

	if offset >= len(body) {
		return nil, errors.New("missing algorithm ID")
	}
	h.Algorithm = AlgorithmID(body[offset])
	offset++

	h.Nonce = make([]byte, len(body)-offset)
	copy(h.Nonce, body[offset:])

	return h, nil
}

func HeaderOverhead(header *Header) int {
	return len(header.Encode())
}
