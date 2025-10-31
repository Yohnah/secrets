package loggermanager

import (
	"bytes"
	"os"
	"testing"
)

func TestStderrLogger_Info(t *testing.T) {
	// Capture stderr
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

func TestStderrLogger_InfoVerbose(t *testing.T) {
	old := os.Stderr
	r, w, _ := os.Pipe()
	os.Stderr = w

	logger := NewStderrLogger()
	logger.SetVerbose(true)
	logger.Info("test message")

	w.Close()
	os.Stderr = old

	var buf bytes.Buffer
	buf.ReadFrom(r)
	output := buf.String()

	expected := "[INFO] test message\n"
	if output != expected {
		t.Errorf("Expected %q, got %q", expected, output)
	}
}

func TestStderrLogger_Debug(t *testing.T) {
	old := os.Stderr
	r, w, _ := os.Pipe()
	os.Stderr = w

	logger := NewStderrLogger()
	logger.Debug("debug message")

	w.Close()
	os.Stderr = old

	var buf bytes.Buffer
	buf.ReadFrom(r)
	output := buf.String()

	// Debug should not output without verbose
	if output != "" {
		t.Errorf("Expected empty output, got %q", output)
	}
}

func TestStderrLogger_DebugVerbose(t *testing.T) {
	old := os.Stderr
	r, w, _ := os.Pipe()
	os.Stderr = w

	logger := NewStderrLogger()
	logger.SetVerbose(true)
	logger.Debug("debug message")

	w.Close()
	os.Stderr = old

	var buf bytes.Buffer
	buf.ReadFrom(r)
	output := buf.String()

	expected := "[DEBUG] debug message\n"
	if output != expected {
		t.Errorf("Expected %q, got %q", expected, output)
	}
}
