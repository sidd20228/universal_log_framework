package detect

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
)

const (
	DefaultMaxSampleBytes = 64 << 10
	HardMaxSampleBytes    = 1 << 20
)

type Sample struct {
	data      []byte
	truncated bool
}

func (sample Sample) Bytes() []byte {
	return bytes.Clone(sample.data)
}

func (sample Sample) Len() int {
	return len(sample.data)
}

func (sample Sample) Truncated() bool {
	return sample.truncated
}

func ReadSample(ctx context.Context, source io.Reader, maximum int) (Sample, error) {
	if source == nil {
		return Sample{}, errors.New("sample source is required")
	}
	if maximum < 1 || maximum > HardMaxSampleBytes {
		return Sample{}, fmt.Errorf("sample maximum must be between 1 and %d bytes", HardMaxSampleBytes)
	}
	if err := ctx.Err(); err != nil {
		return Sample{}, err
	}
	bounded := io.LimitReader(&contextReader{ctx: ctx, source: source}, int64(maximum)+1)
	data, err := io.ReadAll(bounded)
	if err != nil {
		return Sample{}, fmt.Errorf("read detection sample: %w", err)
	}
	truncated := len(data) > maximum
	if truncated {
		data = data[:maximum]
	}
	return Sample{data: bytes.Clone(data), truncated: truncated}, nil
}

type contextReader struct {
	ctx    context.Context
	source io.Reader
}

func (reader *contextReader) Read(buffer []byte) (int, error) {
	if err := reader.ctx.Err(); err != nil {
		return 0, err
	}
	return reader.source.Read(buffer)
}
