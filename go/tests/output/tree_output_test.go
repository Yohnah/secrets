package output_test

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/Yohnah/secrets/internal/output"
)

func TestOutputTreeANSI(t *testing.T) {
	manager := output.NewManager()
	payload := map[string]interface{}{
		"tree": map[string]interface{}{
			"name":     "profile",
			"is_entry": false,
			"status":   "",
			"children": []interface{}{
				map[string]interface{}{
					"name":     "Environment",
					"is_entry": false,
					"status":   "",
					"children": []interface{}{
						map[string]interface{}{
							"name":     "Database",
							"is_entry": true,
							"status":   "exists",
							"children": []interface{}{},
						},
						map[string]interface{}{
							"name":     "API",
							"is_entry": true,
							"status":   "missing",
							"children": []interface{}{},
						},
					},
				},
				map[string]interface{}{
					"name":     "Orphan",
					"is_entry": true,
					"status":   "extra",
					"children": []interface{}{},
				},
			},
		},
		"_display": map[string]interface{}{
			"format": "tree",
			"style":  "ansi",
		},
	}

	outputText := captureOutput(t, func() {
		if err := manager.Output(payload, "tree"); err != nil {
			t.Fatalf("unexpected error rendering ANSI tree: %v", err)
		}
	})

	expectedFragments := []string{
		"profile\n",
		"├── Environment\n",
		"│   ├── Database ✓\n",
		"│   └── API ✗\n",
		"└── Orphan ⚠\n",
	}

	for _, fragment := range expectedFragments {
		if !strings.Contains(outputText, fragment) {
			t.Fatalf("expected output to contain %q, got:\n%s", fragment, outputText)
		}
	}
}

func TestOutputTreeASCII(t *testing.T) {
	manager := output.NewManager()
	payload := map[string]interface{}{
		"tree": map[string]interface{}{
			"name":     "profile",
			"is_entry": false,
			"status":   "",
			"children": []interface{}{
				map[string]interface{}{
					"name":     "Environment",
					"is_entry": false,
					"status":   "",
					"children": []interface{}{
						map[string]interface{}{
							"name":     "Database",
							"is_entry": true,
							"status":   "exists",
							"children": []interface{}{},
						},
						map[string]interface{}{
							"name":     "API",
							"is_entry": true,
							"status":   "missing",
							"children": []interface{}{},
						},
					},
				},
				map[string]interface{}{
					"name":     "Orphan",
					"is_entry": true,
					"status":   "extra",
					"children": []interface{}{},
				},
			},
		},
		"_display": map[string]interface{}{
			"format": "tree",
			"style":  "ascii",
		},
	}

	outputText := captureOutput(t, func() {
		if err := manager.Output(payload, "tree"); err != nil {
			t.Fatalf("unexpected error rendering ASCII tree: %v", err)
		}
	})

	expectedFragments := []string{
		"profile\n",
		"|-- Environment\n",
		"|   |-- Database ✓\n",
		"|   `-- API ✗\n",
		"`-- Orphan ⚠\n",
	}

	for _, fragment := range expectedFragments {
		if !strings.Contains(outputText, fragment) {
			t.Fatalf("expected output to contain %q, got:\n%s", fragment, outputText)
		}
	}
}

func TestOutputTreeInvalidStyle(t *testing.T) {
	manager := output.NewManager()
	payload := map[string]interface{}{
		"tree": map[string]interface{}{
			"name":     "profile",
			"is_entry": false,
			"status":   "",
			"children": []interface{}{},
		},
		"_display": map[string]interface{}{
			"format": "tree",
			"style":  "unsupported",
		},
	}

	err := manager.Output(payload, "tree")
	if err == nil {
		t.Fatalf("expected error for unsupported tree style, got nil")
	}

	if !strings.Contains(err.Error(), "unsupported tree output style") {
		t.Fatalf("unexpected error message: %v", err)
	}
}

func captureOutput(t *testing.T, fn func()) string {
	t.Helper()

	originalStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("failed to create pipe: %v", err)
	}

	os.Stdout = w

	outputCh := make(chan string)
	go func() {
		var buf bytes.Buffer
		_, _ = io.Copy(&buf, r)
		outputCh <- buf.String()
	}()

	fn()

	_ = w.Close()
	os.Stdout = originalStdout
	captured := <-outputCh
	_ = r.Close()

	return captured
}
