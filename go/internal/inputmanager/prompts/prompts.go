package prompts

import (
"bufio"
"fmt"
"os"
"strings"
"golang.org/x/term"
)

type PromptsReader interface {
AskPasswordConfirm(prompt string) (string, error)
AskPassword(prompt string) (string, error)
AskText(prompt string) (string, error)
AskConfirmation(prompt string, defaultValue bool) (bool, error)
AskChoice(prompt string, options []string) (string, error)
}

type StandardPrompts struct{}

func NewStandardPrompts() PromptsReader {
return &StandardPrompts{}
}

func (p *StandardPrompts) AskPasswordConfirm(prompt string) (string, error) {
password1, err := p.AskPassword(prompt)
if err != nil {
return "", err
}
password2, err := p.AskPassword("Repeat your new password: ")
if err != nil {
return "", err
}
if password1 != password2 {
return "", fmt.Errorf("passwords do not match")
}
return password1, nil
}

func (p *StandardPrompts) AskPassword(prompt string) (string, error) {
fmt.Fprintf(os.Stderr, "%s", prompt)
passwordBytes, err := term.ReadPassword(int(os.Stdin.Fd()))
fmt.Fprintln(os.Stderr)
if err != nil {
return "", fmt.Errorf("failed to read password: %w", err)
}
return string(passwordBytes), nil
}

func (p *StandardPrompts) AskText(prompt string) (string, error) {
fmt.Fprintf(os.Stderr, "%s", prompt)
reader := bufio.NewReader(os.Stdin)
response, err := reader.ReadString('\n')
if err != nil {
return "", fmt.Errorf("failed to read input: %w", err)
}
return strings.TrimSpace(response), nil
}

func (p *StandardPrompts) AskConfirmation(prompt string, defaultValue bool) (bool, error) {
var formattedPrompt string
if defaultValue {
formattedPrompt = fmt.Sprintf("%s (Y/n) ", prompt)
} else {
formattedPrompt = fmt.Sprintf("%s (y/N) ", prompt)
}
fmt.Fprintf(os.Stderr, "%s", formattedPrompt)
reader := bufio.NewReader(os.Stdin)
response, err := reader.ReadString('\n')
if err != nil {
return false, fmt.Errorf("failed to read input: %w", err)
}
response = strings.TrimSpace(strings.ToLower(response))
if response == "" {
return defaultValue, nil
}
if response == "y" || response == "yes" {
return true, nil
}
if response == "n" || response == "no" {
return false, nil
}
return defaultValue, nil
}

func (p *StandardPrompts) AskChoice(prompt string, options []string) (string, error) {
if len(options) == 0 {
return "", fmt.Errorf("no options provided")
}
fmt.Fprintf(os.Stderr, "%s\n", prompt)
for i, option := range options {
fmt.Fprintf(os.Stderr, "  %d. %s\n", i+1, option)
}
fmt.Fprintf(os.Stderr, "Enter choice (1-%d): ", len(options))
reader := bufio.NewReader(os.Stdin)
response, err := reader.ReadString('\n')
if err != nil {
return "", fmt.Errorf("failed to read input: %w", err)
}
response = strings.TrimSpace(response)
var choice int
_, err = fmt.Sscanf(response, "%d", &choice)
if err != nil || choice < 1 || choice > len(options) {
return "", fmt.Errorf("invalid choice")
}
return options[choice-1], nil
}
