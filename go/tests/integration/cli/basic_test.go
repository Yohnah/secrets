package cli

import (
	"os/exec"
	"strings"
	"testing"

	integration "github.com/Yohnah/secrets/tests/integration"
	"github.com/stretchr/testify/suite"
)

// CLIBasicSuite tests basic CLI functionality
type CLIBasicSuite struct {
	integration.IntegrationSuite
}

// TestCLIBasicSuite runs the CLI basic test suite
func TestCLIBasicSuite(t *testing.T) {
	suite.Run(t, new(CLIBasicSuite))
}

// TestCLI_NoArguments tests running secrets without arguments
func (s *CLIBasicSuite) TestCLI_NoArguments() {
	cmd := exec.Command(s.BinPath)
	output, err := cmd.CombinedOutput()

	// Should show help and exit with 0
	s.NoError(err, "secrets without arguments should exit 0")

	outputStr := string(output)
	s.Contains(outputStr, "Usage:", "Output should contain usage information")
	s.Contains(outputStr, "secrets", "Output should contain command name")
}

// TestCLI_Help tests the --help flag
func (s *CLIBasicSuite) TestCLI_Help() {
	cmd := exec.Command(s.BinPath, "--help")
	output, err := cmd.CombinedOutput()

	s.NoError(err, "secrets --help should exit 0")

	outputStr := string(output)
	s.Contains(outputStr, "Usage:", "Help output should contain usage")
	s.Contains(outputStr, "Available Commands:", "Help should list commands")
	s.Contains(outputStr, "Flags:", "Help should list flags")
}

// TestCLI_Version tests the --version flag
func (s *CLIBasicSuite) TestCLI_Version() {
	cmd := exec.Command(s.BinPath, "--version")
	output, err := cmd.CombinedOutput()

	s.NoError(err, "secrets --version should exit 0")

	outputStr := strings.TrimSpace(string(output))
	// Version should be in format: vX.Y.Z or commit hash
	s.NotEmpty(outputStr, "Version output should not be empty")
}

// TestCLI_InvalidCommand tests running secrets with invalid command
func (s *CLIBasicSuite) TestCLI_InvalidCommand() {
	cmd := exec.Command(s.BinPath, "invalid-command")
	output, err := cmd.CombinedOutput()

	s.Error(err, "Invalid command should exit with error")

	outputStr := string(output)
	s.Contains(outputStr, "unknown command", "Should indicate unknown command")
}

// TestCLI_InvalidFlag tests running secrets with invalid flag
func (s *CLIBasicSuite) TestCLI_InvalidFlag() {
	cmd := exec.Command(s.BinPath, "--invalid-flag")
	output, err := cmd.CombinedOutput()

	s.Error(err, "Invalid flag should exit with error")

	outputStr := string(output)
	s.Contains(outputStr, "unknown flag", "Should indicate unknown flag")
}

// TestCLI_HelpCommand tests the help command
func (s *CLIBasicSuite) TestCLI_HelpCommand() {
	cmd := exec.Command(s.BinPath, "help", "init")
	output, err := cmd.CombinedOutput()

	s.NoError(err, "help init should exit 0")

	outputStr := string(output)
	s.Contains(outputStr, "init", "Help for init should mention the command")
	s.Contains(outputStr, "Usage:", "Should show usage")
}
