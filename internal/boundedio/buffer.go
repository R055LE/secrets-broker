// Package boundedio provides fixed-memory output capture for child processes.
package boundedio

import "bytes"

// Buffer retains at most limit bytes while continuing to consume writes.
type Buffer struct {
	buf      bytes.Buffer
	limit    int
	exceeded bool
}

func NewBuffer(limit int) *Buffer {
	return &Buffer{limit: limit}
}

func (b *Buffer) Write(p []byte) (int, error) {
	remaining := b.limit - b.buf.Len()
	if remaining < len(p) {
		b.exceeded = true
		if remaining > 0 {
			_, _ = b.buf.Write(p[:remaining])
		}
		return len(p), nil
	}
	_, _ = b.buf.Write(p)
	return len(p), nil
}

func (b *Buffer) Bytes() []byte {
	return b.buf.Bytes()
}

func (b *Buffer) String() string {
	return b.buf.String()
}

func (b *Buffer) Exceeded() bool {
	return b.exceeded
}
