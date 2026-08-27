package boundedio

import "testing"

func TestBufferCapsAndConsumesWrites(t *testing.T) {
	buf := NewBuffer(4)
	n, err := buf.Write([]byte("secret-response"))
	if err != nil || n != len("secret-response") {
		t.Fatalf("Write() = %d, %v", n, err)
	}
	if got := buf.String(); got != "secr" {
		t.Fatalf("String() = %q", got)
	}
	if !buf.Exceeded() {
		t.Fatal("Exceeded() = false")
	}
}
