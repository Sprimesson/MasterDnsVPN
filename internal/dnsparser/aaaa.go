package dnsparser

import (
	"errors"
	"fmt"
	"math/rand"
	"time"
)

const (
	aaaaMaxInputSize = 480
	aaaaChunkDataLen = 15
	aaaaChunkLen     = 16
	aaaaMaxChunks    = 32
)

func BuildAAAAAnswerChunks(in []byte) ([][]byte, error) {
	if len(in) == 0 {
		return nil, errors.New("input must not be empty")
	}
	if len(in) > aaaaMaxInputSize {
		return nil, fmt.Errorf("input too large: %d > %d", len(in), aaaaMaxInputSize)
	}

	n := (len(in) + aaaaChunkDataLen - 1) / aaaaChunkDataLen
	if n > aaaaMaxChunks {
		return nil, fmt.Errorf("too many chunks: %d > %d", n, aaaaMaxChunks)
	}

	out := make([][]byte, n)
	for i := 0; i < n; i++ {
		start := i * aaaaChunkDataLen
		end := start + aaaaChunkDataLen
		if end > len(in) {
			end = len(in)
		}

		payload := in[start:end]
		chunk := make([]byte, aaaaChunkLen)

		switch {
		case n == 1:
			chunk[0] = 0xF0 + byte(len(payload)) // Case B
		case i == n-1:
			chunk[0] = 0xF0 + byte(len(payload)) // Case B
		case i == n-2:
			chunk[0] = 0x80 + byte(i) // Case C
		default:
			chunk[0] = 0x20 + byte(i) // Case A
		}

		copy(chunk[1:], payload)
		out[i] = chunk
	}

	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	r.Shuffle(len(out), func(i, j int) {
		out[i], out[j] = out[j], out[i]
	})

	return out, nil
}

func ExtractAAAABytes(chunks [][]byte) ([]byte, error) {
	if len(chunks) == 0 {
		return nil, errors.New("no chunks provided")
	}
	if len(chunks) > aaaaMaxChunks {
		return nil, fmt.Errorf("too many chunks: %d > %d", len(chunks), aaaaMaxChunks)
	}

	var (
		caseBCount int
		caseCCount int
		total      int
		lastChunk  []byte
	)

	for _, ch := range chunks {
		if len(ch) != aaaaChunkLen {
			return nil, fmt.Errorf("invalid chunk length: got %d, want %d", len(ch), aaaaChunkLen)
		}

		h := ch[0]
		switch {
		case h >= 0xF1 && h <= 0xFF: // Case B
			caseBCount++
			lastChunk = ch
		case h >= 0x80 && h <= 0x9F: // Case C
			caseCCount++
			total = int(h-0x80) + 2
		case h >= 0x20 && h <= 0x3F: // Case A
		default:
			return nil, fmt.Errorf("invalid header byte: 0x%02X", h)
		}
	}

	if caseBCount != 1 {
		return nil, fmt.Errorf("expected exactly 1 Case B chunk, got %d", caseBCount)
	}

	if caseCCount == 0 {
		if len(chunks) != 1 {
			return nil, errors.New("missing Case C chunk for multi-chunk message")
		}
		size := int(lastChunk[0] - 0xF0)
		return append([]byte(nil), lastChunk[1:1+size]...), nil
	}

	if caseCCount != 1 {
		return nil, fmt.Errorf("expected exactly 1 Case C chunk, got %d", caseCCount)
	}
	if total < len(chunks) {
		return nil, fmt.Errorf("incomplete: expected %d, got %d", total, len(chunks))
	}

	ordered := make([][]byte, total)
	for _, ch := range chunks {
		h := ch[0]

		switch {
		case h >= 0x20 && h <= 0x3F:
			idx := int(h - 0x20)
			if idx < 0 || idx >= total-2 {
				return nil, fmt.Errorf("Case A index out of range: %d", idx)
			}
			if ordered[idx] != nil {
				return nil, fmt.Errorf("duplicate chunk index: %d", idx)
			}
			ordered[idx] = ch

		case h >= 0x80 && h <= 0x9F:
			idx := int(h - 0x80)
			if idx != total-2 {
				return nil, fmt.Errorf("Case C index mismatch: got %d, want %d", idx, total-2)
			}
			if ordered[idx] != nil {
				return nil, fmt.Errorf("duplicate chunk index: %d", idx)
			}
			ordered[idx] = ch

		case h >= 0xF1 && h <= 0xFF:
			idx := total - 1
			if ordered[idx] != nil {
				return nil, fmt.Errorf("duplicate last chunk")
			}
			ordered[idx] = ch
		}
	}

	for i, ch := range ordered {
		if ch == nil {
			return nil, fmt.Errorf("missing chunk index: %d", i)
		}
	}

	out := make([]byte, 0, total*aaaaChunkDataLen)
	for i, ch := range ordered {
		if i == total-1 {
			size := int(ch[0] - 0xF0)
			out = append(out, ch[1:1+size]...)
		} else {
			out = append(out, ch[1:]...)
		}
	}

	return out, nil
}
