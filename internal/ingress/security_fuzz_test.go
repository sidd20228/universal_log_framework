package ingress

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"reflect"
	"testing"

	"github.com/sidd20228/universal_log_framework/internal/model"
)

func FuzzTCPFraming(f *testing.F) {
	seeds := []struct {
		octetCounted bool
		wire         []byte
		delimiter    []byte
		maximum      uint16
	}{
		{true, []byte("5 hello"), nil, 64},
		{true, []byte("999999999999999999999 x"), nil, 8},
		{true, []byte("5 abc"), nil, 8},
		{false, []byte("first\r\nsecond\r\n"), []byte("\r\n"), 64},
		{false, []byte("incomplete"), []byte{'\n'}, 8},
		{false, []byte("\n"), []byte{'\n'}, 8},
	}
	for _, seed := range seeds {
		f.Add(seed.octetCounted, seed.wire, seed.delimiter, seed.maximum)
	}
	f.Fuzz(func(t *testing.T, octetCounted bool, wire, delimiter []byte, maximumSeed uint16) {
		if len(wire) > 64<<10 || len(delimiter) > maximumTCPDelimiterSize {
			return
		}
		maximum := int(maximumSeed%4096) + 1
		mode := model.FramingNonTransparent
		if octetCounted {
			mode = model.FramingOctetCounting
			delimiter = nil
		}
		firstFrame, firstErr := readTCPFrame(bufio.NewReader(bytes.NewReader(wire)), mode, delimiter, maximum, nil)
		secondFrame, secondErr := readTCPFrame(bufio.NewReader(bytes.NewReader(wire)), mode, delimiter, maximum, nil)
		if !bytes.Equal(firstFrame, secondFrame) || tcpFrameErrorClass(firstErr) != tcpFrameErrorClass(secondErr) {
			t.Fatalf("framing is nondeterministic: first=(%x, %v) second=(%x, %v)", firstFrame, firstErr, secondFrame, secondErr)
		}
		if firstErr == nil {
			if len(firstFrame) == 0 || len(firstFrame) > maximum {
				t.Fatalf("accepted frame length %d outside 1..%d", len(firstFrame), maximum)
			}
			return
		}
		if firstFrame != nil {
			t.Fatalf("rejected framing retained bytes: %x", firstFrame)
		}
	})
}

func TestSecurityTCPFramingCorpus(t *testing.T) {
	tests := []struct {
		name      string
		wire      []byte
		mode      model.FramingMode
		delimiter []byte
		maximum   int
		want      error
	}{
		{name: "leading zero", wire: []byte("05 hello"), mode: model.FramingOctetCounting, maximum: 8, want: ErrTCPInvalidOctetCount},
		{name: "count overflow", wire: []byte("999999999999999999999 x"), mode: model.FramingOctetCounting, maximum: 8, want: ErrTCPInvalidOctetCount},
		{name: "short frame", wire: []byte("5 abc"), mode: model.FramingOctetCounting, maximum: 8, want: ErrTCPIncompleteFrame},
		{name: "oversize declared", wire: []byte("9 ignored"), mode: model.FramingOctetCounting, maximum: 8, want: ErrTCPFrameTooLarge},
		{name: "delimiter injection first frame", wire: []byte("first\ninjected\n"), mode: model.FramingNonTransparent, delimiter: []byte{'\n'}, maximum: 64},
		{name: "missing delimiter", wire: []byte("event"), mode: model.FramingNonTransparent, delimiter: []byte{'\n'}, maximum: 8, want: ErrTCPIncompleteFrame},
		{name: "empty delimiter frame", wire: []byte("\n"), mode: model.FramingNonTransparent, delimiter: []byte{'\n'}, maximum: 8, want: ErrTCPEmptyFrame},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			frame, err := readTCPFrame(bufio.NewReader(bytes.NewReader(test.wire)), test.mode, test.delimiter, test.maximum, nil)
			if test.want != nil && !errors.Is(err, test.want) {
				t.Fatalf("error = %v, want %v", err, test.want)
			}
			if test.want == nil && (err != nil || !bytes.Equal(frame, []byte("first"))) {
				t.Fatalf("frame = %q, error = %v", frame, err)
			}
		})
	}
}

func tcpFrameErrorClass(err error) string {
	for _, candidate := range []error{
		io.EOF,
		ErrTCPUnsupportedFraming,
		ErrTCPInvalidOctetCount,
		ErrTCPFrameTooLarge,
		ErrTCPIncompleteFrame,
		ErrTCPEmptyFrame,
		ErrTCPReadTimeout,
	} {
		if errors.Is(err, candidate) {
			return candidate.Error()
		}
	}
	if err == nil {
		return ""
	}
	return reflect.TypeOf(err).String() + ":" + err.Error()
}
