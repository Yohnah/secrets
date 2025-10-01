package prompt

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/Yohnah/secrets/internal/logger"
)

// InteractivePrompter interface follows ISP - Interface Segregation Principle
// Separates user interaction concerns
type InteractivePrompter interface {
	AskYesNo(question, defaultOption string, forceDefault bool) (bool, error)
	AskString(question, defaultOption string, forceDefault bool) (string, error)
}

// DefaultInteractivePrompter follows SRP - Single Responsibility for user interaction
type DefaultInteractivePrompter struct {
	logger logger.Logger
	reader *bufio.Reader
}

// NewInteractivePrompter factory function follows DIP - Dependency Inversion Principle
func NewInteractivePrompter(logger logger.Logger) InteractivePrompter {
	return &DefaultInteractivePrompter{
		logger: logger,
		reader: bufio.NewReader(os.Stdin),
	}
}

// AskYesNo asks a yes/no question with the specified format
// Format: "Question text. (yes, no) [default: defaultOption]"
func (p *DefaultInteractivePrompter) AskYesNo(question, defaultOption string, forceDefault bool) (bool, error) {
	if forceDefault {
		p.logger.Debug("Force mode enabled, using default: " + defaultOption)
		return p.parseYesNo(defaultOption), nil
	}
	
	// Format the question according to specification
	prompt := fmt.Sprintf("%s (yes, no) [default: %s]: ", question, defaultOption)
	
	for {
		fmt.Print(prompt)
		
		input, err := p.reader.ReadString('\n')
		if err != nil {
			return false, fmt.Errorf("failed to read input: %v", err)
		}
		
		input = strings.TrimSpace(input)
		
		// If empty input, use default
		if input == "" {
			p.logger.Debug("Using default option: " + defaultOption)
			return p.parseYesNo(defaultOption), nil
		}
		
		// Parse the input
		input = strings.ToLower(input)
		if input == "yes" || input == "y" {
			return true, nil
		}
		if input == "no" || input == "n" {
			return false, nil
		}
		
		// Invalid input, ask again
		fmt.Printf("Invalid input. Please enter 'yes' or 'no'.\n")
	}
}

// AskString asks a string question with the specified format
// Format: "Question text. [default: defaultOption]"
func (p *DefaultInteractivePrompter) AskString(question, defaultOption string, forceDefault bool) (string, error) {
	if forceDefault {
		p.logger.Debug("Force mode enabled, using default: " + defaultOption)
		return defaultOption, nil
	}
	
	// Format the question according to specification
	var prompt string
	if defaultOption != "" {
		prompt = fmt.Sprintf("%s [default: %s]: ", question, defaultOption)
	} else {
		prompt = fmt.Sprintf("%s: ", question)
	}
	
	fmt.Print(prompt)
	
	input, err := p.reader.ReadString('\n')
	if err != nil {
		return "", fmt.Errorf("failed to read input: %v", err)
	}
	
	input = strings.TrimSpace(input)
	
	// If empty input and there's a default, use it
	if input == "" && defaultOption != "" {
		p.logger.Debug("Using default option: " + defaultOption)
		return defaultOption, nil
	}
	
	return input, nil
}

// parseYesNo converts string to boolean
func (p *DefaultInteractivePrompter) parseYesNo(input string) bool {
	input = strings.ToLower(strings.TrimSpace(input))
	return input == "yes" || input == "y" || input == "true" || input == "1"
}