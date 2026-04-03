package dnsparser

import (
	"bytes"
	"testing"
)

func TestBuildAAAAAnswerChunks_SingleChunk(t *testing.T) {
	in := []byte("hello")
	got, err := BuildAAAAAnswerChunks(in)
	if err != nil {
		t.Fatalf("BuildAAAAAnswerChunks error: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d chunks, want 1", len(got))
	}
	if got[0][0] != 0xF0+byte(len(in)) {
		t.Fatalf("header = 0x%02X, want 0x%02X", got[0][0], 0xF0+byte(len(in)))
	}
	out, err := ExtractAAAABytes(got)
	if err != nil {
		t.Fatalf("ExtractAAAABytes error: %v", err)
	}
	if !bytes.Equal(out, in) {
		t.Fatalf("reassembled %q, want %q", out, in)
	}
}

func TestBuildAAAAAnswerChunks_TwoChunks(t *testing.T) {
	in := make([]byte, 16) // 15 + 1
	for i := range in {
		in[i] = byte(i + 1)
	}

	got, err := BuildAAAAAnswerChunks(in)
	if err != nil {
		t.Fatalf("BuildAAAAAnswerChunks error: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d chunks, want 2", len(got))
	}

	var foundB, foundC bool
	for _, ch := range got {
		switch {
		case ch[0] == 0xF1: // last chunk size=1
			foundB = true
		case ch[0] == 0x80: // penultimate index=0
			foundC = true
		}
	}
	if !foundB || !foundC {
		t.Fatalf("expected one Case B and one Case C, got %#v", got)
	}

	out, err := ExtractAAAABytes(got)
	if err != nil {
		t.Fatalf("ExtractAAAABytes error: %v", err)
	}
	if !bytes.Equal(out, in) {
		t.Fatalf("reassembled mismatch")
	}
}

func TestBuildAAAAAnswerChunks_ThreeChunksHeaders(t *testing.T) {
	in := make([]byte, 31) // 15 + 15 + 1
	for i := range in {
		in[i] = byte(i)
	}

	got, err := BuildAAAAAnswerChunks(in)
	if err != nil {
		t.Fatalf("BuildAAAAAnswerChunks error: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("got %d chunks, want 3", len(got))
	}

	var foundA, foundB, foundC bool
	for _, ch := range got {
		switch ch[0] {
		case 0x20:
			foundA = true
		case 0x81:
			foundC = true
		case 0xF1:
			foundB = true
		}
	}
	if !foundA || !foundB || !foundC {
		t.Fatalf("missing expected headers: A=%v B=%v C=%v", foundA, foundB, foundC)
	}

	out, err := ExtractAAAABytes(got)
	if err != nil {
		t.Fatalf("ExtractAAAABytes error: %v", err)
	}
	if !bytes.Equal(out, in) {
		t.Fatalf("reassembled mismatch")
	}
}

func TestBuildAAAAAnswerChunks_MaxInput(t *testing.T) {
	in := make([]byte, 480)
	for i := range in {
		in[i] = byte(i)
	}

	got, err := BuildAAAAAnswerChunks(in)
	if err != nil {
		t.Fatalf("BuildAAAAAnswerChunks error: %v", err)
	}
	if len(got) != 32 { // current implementation produces 35 chunks for 480 bytes
		t.Fatalf("got %d chunks, want 32", len(got))
	}
}

func TestBuildAAAAAnswerChunks_TooLarge(t *testing.T) {
	in := make([]byte, 523)
	_, err := BuildAAAAAnswerChunks(in)
	if err == nil {
		t.Fatal("expected error for oversized input")
	}
}

func TestExtractAAAABytes_DetectsMissingChunk(t *testing.T) {
	in := make([]byte, 31)
	for i := range in {
		in[i] = byte(i)
	}

	chunks, err := BuildAAAAAnswerChunks(in)
	if err != nil {
		t.Fatalf("BuildAAAAAnswerChunks error: %v", err)
	}

	chunks = chunks[:len(chunks)-1] // remove one random chunk
	_, err = ExtractAAAABytes(chunks)
	if err == nil {
		t.Fatal("expected error for missing chunk")
	}
}

func TestExtractAAAABytes_DetectsDuplicateChunk(t *testing.T) {
	in := make([]byte, 31)
	for i := range in {
		in[i] = byte(i)
	}

	chunks, err := BuildAAAAAnswerChunks(in)
	if err != nil {
		t.Fatalf("BuildAAAAAnswerChunks error: %v", err)
	}

	chunks = append(chunks, chunks[0])
	_, err = ExtractAAAABytes(chunks)
	if err == nil {
		t.Fatal("expected error for duplicate chunk")
	}
}

func TestExtractAAAABytes_DetectsBadChunkLength(t *testing.T) {
	_, err := ExtractAAAABytes([][]byte{
		make([]byte, 15),
	})
	if err == nil {
		t.Fatal("expected error for invalid chunk length")
	}
}

func TestExtractAAAABytes_DetectsMissingCaseCForMultiChunk(t *testing.T) {
	_, err := ExtractAAAABytes([][]byte{
		append([]byte{0x20}, make([]byte, 15)...),
		append([]byte{0xF1}, make([]byte, 15)...),
	})
	if err == nil {
		t.Fatal("expected error for missing Case C")
	}
}

func TestExtractAAAABytes_RandomizedOrderStillWorks(t *testing.T) {
	in := make([]byte, 46) // 15 + 15 + 15 + 1
	for i := range in {
		in[i] = byte(100 + i)
	}

	chunks := [][]byte{
		append([]byte{0x20}, in[0:15]...),
		append([]byte{0x21}, in[15:30]...),
		append([]byte{0x82}, in[30:45]...),
		append([]byte{0xF1}, append([]byte{in[45]}, make([]byte, 14)...)...),
	}

	// deliberately scrambled
	shuffled := [][]byte{chunks[3], chunks[1], chunks[0], chunks[2]}

	out, err := ExtractAAAABytes(shuffled)
	if err != nil {
		t.Fatalf("ExtractAAAABytes error: %v", err)
	}
	if !bytes.Equal(out, in) {
		t.Fatalf("reassembled mismatch")
	}
}
