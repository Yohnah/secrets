package loggermanager

import (
	"bytes"
	"os"
	"testing"
)

func TestNewStderrLogger(t *testing.T) {
	logger := NewStderrLogger()
	if logger == nil {
		t.Error("Expected non-nil logger")
	}
}

func TestStderrLogger_Info(t *testing.T) {
	old := os.Stderr
	r, w, _ := os.Pipe()
	os.Stderr = w

	logger := NewStderrLogger()
	logger.Info("test message")

	w.Close()
	os.Stderr = old

	var buf bytes.Buffer
	buf.ReadFrom(r)
	output := buf.String()

	expected := "test message\n"
	if output != expected {
		t.Errorf("Expected %q, got %q", expected, output)
	}
}
