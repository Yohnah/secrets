package cli

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// ConfirmationProvider interface for asking user confirmations
type ConfirmationProvider interface {
	Confirm(message string) (bool, error)
}

// InteractiveConfirmationProvider handles interactive confirmations
type InteractiveConfirmationProvider struct {
	logger Logger
}

// NewConfirmationProvider creates a new confirmation provider
func NewConfirmationProvider(logger Logger) ConfirmationProvider {
	return &InteractiveConfirmationProvider{
		logger: logger,
	}
}

// Confirm asks the user for confirmation with a yes/no question
func (p *InteractiveConfirmationProvider) Confirm(message string) (bool, error) {
	reader := bufio.NewReader(os.Stdin)
	
	for {
		fmt.Printf("%s (y/N): ", message)
		response, err := reader.ReadString('\n')
		if err != nil {
			return false, fmt.Errorf("failed to read input: %v", err)
		}
		
		// Clean up the response
		response = strings.TrimSpace(strings.ToLower(response))
		
		switch response {
		case "y", "yes":
			return true, nil
		case "n", "no", "":
			return false, nil
		default:
			fmt.Println("Please answer 'y' for yes or 'n' for no.")
		}
	}
}