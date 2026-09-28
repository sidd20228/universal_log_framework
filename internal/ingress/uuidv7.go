package ingress

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"sync"
	"time"
)

type uuidv7Generator struct {
	mu       sync.Mutex
	random   io.Reader
	lastMS   int64
	sequence uint16
}

func newUUIDv7Generator() *uuidv7Generator {
	return &uuidv7Generator{random: rand.Reader, lastMS: -1}
}

func (generator *uuidv7Generator) New(now time.Time) (string, error) {
	generator.mu.Lock()
	defer generator.mu.Unlock()

	milliseconds := now.UnixMilli()
	if milliseconds < 0 || milliseconds > 0xFFFFFFFFFFFF {
		return "", fmt.Errorf("time is outside UUIDv7 range")
	}
	if milliseconds <= generator.lastMS {
		milliseconds = generator.lastMS
		if generator.sequence == 0x0fff {
			milliseconds++
			generator.sequence = 0
		} else {
			generator.sequence++
		}
	} else {
		var seed [2]byte
		if _, err := io.ReadFull(generator.random, seed[:]); err != nil {
			return "", fmt.Errorf("read UUIDv7 sequence entropy: %w", err)
		}
		generator.sequence = binary.BigEndian.Uint16(seed[:]) & 0x0fff
	}
	if milliseconds > 0xFFFFFFFFFFFF {
		return "", fmt.Errorf("time is outside UUIDv7 range")
	}
	generator.lastMS = milliseconds

	var value [16]byte
	value[0] = byte(milliseconds >> 40)
	value[1] = byte(milliseconds >> 32)
	value[2] = byte(milliseconds >> 24)
	value[3] = byte(milliseconds >> 16)
	value[4] = byte(milliseconds >> 8)
	value[5] = byte(milliseconds)
	value[6] = 0x70 | byte(generator.sequence>>8)
	value[7] = byte(generator.sequence)
	if _, err := io.ReadFull(generator.random, value[8:]); err != nil {
		return "", fmt.Errorf("read UUIDv7 entropy: %w", err)
	}
	value[8] = (value[8] & 0x3f) | 0x80
	return formatUUID(value), nil
}

func formatUUID(value [16]byte) string {
	return fmt.Sprintf(
		"%08x-%04x-%04x-%04x-%012x",
		value[0:4],
		value[4:6],
		value[6:8],
		value[8:10],
		value[10:16],
	)
}
