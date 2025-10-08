package show

import (
	"fmt"
	"strings"
	"unicode"

	"github.com/Yohnah/secrets/internal/secrets/common"
	"github.com/Yohnah/secrets/internal/validator"
)

// TreeNode represents a node in the tree structure
type TreeNode struct {
	Name     string
	IsEntry  bool
	Status   string // "", "exists", "missing", "extra"
	Children []*TreeNode
}

// Tree displays a tree representation of the specified profile and environment
func (s *service) Tree(profileName, environmentName, outputFormat string) error {
	// Validate output format
	if outputFormat != "ansi" && outputFormat != "ascii" {
		return fmt.Errorf("invalid output format '%s': must be 'ansi' or 'ascii'", outputFormat)
	}

	// Get secrets.yml path from config
	secretsFilePath := s.config.GetSecretsFilePath()

	// Validate that profile and environment exist in secrets.yml
	secretsConfig, errs := s.validator.ReadAndValidateSecretsYML(secretsFilePath)
	if len(errs) > 0 {
		return fmt.Errorf("invalid secrets.yml: %v", errs[0])
	}

	// Find the profile
	var found bool
	for _, profile := range secretsConfig.Profiles {
		if profile.Metadata.Profile == profileName {
			found = true
			// Check if environment exists
			if _, exists := profile.Environments[environmentName]; !exists {
				return fmt.Errorf("environment '%s' does not exist in profile '%s'", environmentName, profileName)
			}
			break
		}
	}

	if !found {
		return fmt.Errorf("profile '%s' does not exist in secrets.yml", profileName)
	}

	// Get configuration
	cfg, err := s.config.GetConfig()
	if err != nil {
		return fmt.Errorf("failed to get configuration: %w", err)
	}

	// Get password (secure)
	securePassword, err := common.GetPassword(cfg, s.prompt, s.logger, false)
	if err != nil {
		return err
	}
	defer securePassword.Clear() // Ensure password is cleared from memory

	// Open database
	dbPath := s.config.GetDatabasePath()
	keyfilePath := s.config.GetKeyfilePath()

	err = s.keepass.Open(dbPath, keyfilePath, securePassword.String())
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}
	defer s.keepass.CloseWithoutSave()

	// Build tree structure
	root, err := s.buildTree(secretsConfig, profileName, environmentName)
	if err != nil {
		return err
	}

	// Display the tree
	s.displayTree(root, outputFormat == "ansi")

	return nil
}

// buildTree builds the tree structure from secrets.yml and database
func (s *service) buildTree(secretsConfig interface{}, profileName, environmentName string) (*TreeNode, error) {
	// Get entries defined in secrets.yml for this environment
	secretsYMLEntries := make(map[string]bool)

	// Type assert to get the actual config structure
	config, ok := secretsConfig.(*validator.SecretsConfig)
	if !ok {
		return nil, fmt.Errorf("invalid secrets config type")
	}

	// Find the profile and environment
	var targetProfile *validator.Profile
	for i := range config.Profiles {
		if config.Profiles[i].Metadata.Profile == profileName {
			targetProfile = &config.Profiles[i]
			break
		}
	}

	if targetProfile == nil {
		return nil, fmt.Errorf("profile '%s' not found", profileName)
	}

	// Get all entries defined in secrets.yml for this environment
	environmentNameCapitalized := capitalizeEnvironmentName(environmentName)
	for _, item := range targetProfile.Environments[environmentName] {
		// Trim the environment prefix from the entry path
		// Example: "/Production/Database/PostgreSQL" -> "Database/PostgreSQL"
		relativePath := strings.TrimPrefix(item.Entry, fmt.Sprintf("/%s/", environmentNameCapitalized))
		secretsYMLEntries[relativePath] = true
	}

	// Get all entries from database
	dbEntries, err := s.keepass.GetEntriesByEnvironment(profileName, environmentName)
	if err != nil {
		return nil, fmt.Errorf("failed to get entries from database: %w", err)
	}

	// Convert db entries to map for easy lookup
	dbEntriesMap := make(map[string]bool)
	for _, entry := range dbEntries {
		dbEntriesMap[entry] = true
	}

	// Build root node (profile)
	root := &TreeNode{
		Name:     profileName,
		IsEntry:  false,
		Status:   "exists",
		Children: []*TreeNode{},
	}

	// Build environment node (use capitalized name for display)
	envNode := &TreeNode{
		Name:     environmentNameCapitalized,
		IsEntry:  false,
		Status:   "exists",
		Children: []*TreeNode{},
	}

	// Process entries defined in secrets.yml
	for entryPath := range secretsYMLEntries {
		status := "missing"
		if dbEntriesMap[entryPath] {
			status = "exists"
		}
		s.addPathToTree(envNode, entryPath, status)
	}

	// Process entries that exist in DB but not in secrets.yml
	for dbPath := range dbEntriesMap {
		if !secretsYMLEntries[dbPath] {
			s.addPathToTree(envNode, dbPath, "extra")
		}
	}

	root.Children = append(root.Children, envNode)
	return root, nil
}

// addPathToTree adds a path to the tree structure
func (s *service) addPathToTree(parent *TreeNode, path string, status string) {
	if path == "" {
		return
	}

	// Split the path into parts
	parts := strings.Split(path, "/")
	current := parent

	for i, part := range parts {
		isLast := i == len(parts)-1

		// Find if this node already exists
		var child *TreeNode
		for _, c := range current.Children {
			if c.Name == part {
				child = c
				break
			}
		}

		// Create new node if it doesn't exist
		if child == nil {
			child = &TreeNode{
				Name:     part,
				IsEntry:  isLast,
				Status:   "",
				Children: []*TreeNode{},
			}

			// Only set status on leaf nodes (entries)
			if isLast {
				child.Status = status
			}

			current.Children = append(current.Children, child)
		}

		current = child
	}
}

// displayTree displays the tree structure
func (s *service) displayTree(node *TreeNode, useAnsi bool) {
	// Print the root node (profile) first using output manager
	s.output.OutputRaw(node.Name + "\n")

	// Print children with proper tree structure
	for i, child := range node.Children {
		isLast := i == len(node.Children)-1
		s.printNodeWithPrefix(child, "", isLast, useAnsi)
	}
}

// capitalizeEnvironmentName capitalizes the first letter of each word in the environment name
// This replaces the deprecated strings.Title function
func capitalizeEnvironmentName(name string) string {
	if name == "" {
		return name
	}

	// Convert to lowercase first
	name = strings.ToLower(name)

	// Capitalize first letter
	runes := []rune(name)
	runes[0] = unicode.ToUpper(runes[0])

	return string(runes)
}

// printNodeWithPrefix recursively prints a tree node with prefix
func (s *service) printNodeWithPrefix(node *TreeNode, prefix string, isLast bool, useAnsi bool) {
	if node == nil {
		return
	}

	// Determine connector for current node
	var connector string
	if useAnsi {
		if isLast {
			connector = "└── "
		} else {
			connector = "├── "
		}
	} else {
		if isLast {
			connector = "`-- "
		} else {
			connector = "|-- "
		}
	}

	// Build status indicator
	statusStr := ""
	if node.IsEntry {
		switch node.Status {
		case "exists":
			statusStr = " ✓"
		case "missing":
			statusStr = " ✗"
		case "extra":
			statusStr = " ⚠"
		}
	}

	// Print current node using output manager
	line := prefix + connector + node.Name + statusStr + "\n"
	s.output.OutputRaw(line)

	// Prepare prefix for children
	var childPrefix string
	if useAnsi {
		if isLast {
			childPrefix = prefix + "    "
		} else {
			childPrefix = prefix + "│   "
		}
	} else {
		if isLast {
			childPrefix = prefix + "    "
		} else {
			childPrefix = prefix + "|   "
		}
	}

	// Print children
	for i, child := range node.Children {
		s.printNodeWithPrefix(child, childPrefix, i == len(node.Children)-1, useAnsi)
	}
}
