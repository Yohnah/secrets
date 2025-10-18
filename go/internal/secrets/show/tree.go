package show

import (
	"fmt"
	"strings"

	"github.com/Yohnah/secrets/internal/secrets/common"
	"github.com/Yohnah/secrets/internal/validator"
)

// TreeNode represents a node in the tree structure
type TreeNode struct {
	Name     string
	IsEntry  bool
	IsKey    bool   // New: indicates if this is a key/field
	Status   string // "", "exists", "missing", "extra"
	Children []*TreeNode
}

// Tree displays a tree representation of the specified profile and environment
func (s *service) Tree(environmentName, outputFormat string) error {
	// Validate output format
	if outputFormat != "ansi" && outputFormat != "ascii" {
		return fmt.Errorf("invalid output format '%s': must be 'ansi' or 'ascii'", outputFormat)
	}

	// Resolve profile (auto-detect when possible)
	resolvedProfile, err := s.profileResolver.Resolve("")
	if err != nil {
		return err
	}
	profileName := resolvedProfile.Name

	if resolvedProfile.Profile == nil {
		return fmt.Errorf("profile '%s' is invalid in secrets.yml", profileName)
	}

	environmentItems, exists := resolvedProfile.Profile.Environments[environmentName]
	if !exists {
		return fmt.Errorf("environment '%s' does not exist in profile '%s'", environmentName, profileName)
	}

	// Get configuration
	// Get configuration (not used for password, but kept for consistency)
	_, err = s.config.GetConfig()
	if err != nil {
		return fmt.Errorf("failed to get configuration: %w", err)
	}

	// Get password (secure)
	securePassword, err := common.GetPassword(s.config, s.prompt, s.logger, false)
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

	// Validate database integrity
	if errs := s.validator.ValidateKeePassDuplicates(s.keepass); len(errs) > 0 {
		return fmt.Errorf("database corruption detected: %v", errs[0])
	}

	// Build tree structure
	root, err := s.buildTree(profileName, environmentName, environmentItems)
	if err != nil {
		return err
	}

	// Render tree using output manager
	return s.renderTree(root, outputFormat)
}

// buildTree builds the tree structure from secrets.yml and database
func (s *service) buildTree(profileName, environmentName string, environmentItems []validator.Item) (*TreeNode, error) {
	// Get entries defined in secrets.yml for this environment
	secretsYMLEntries := make(map[string]bool)
	secretsYMLKeys := make(map[string]map[string]bool) // entryPath -> map of keys

	for _, item := range environmentItems {
		// Use entry path exactly as specified in secrets.yml (only remove leading slash)
		entryPath := item.Entry
		if len(entryPath) > 0 && entryPath[0] == '/' {
			entryPath = entryPath[1:]
		}

		secretsYMLEntries[entryPath] = true

		// Add key to the entry's key map
		if secretsYMLKeys[entryPath] == nil {
			secretsYMLKeys[entryPath] = make(map[string]bool)
		}
		secretsYMLKeys[entryPath][item.Key] = true
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

	// Build environment node (use exact name from secrets.yml)
	envNode := &TreeNode{
		Name:     environmentName,
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
		s.addPathToTree(envNode, entryPath, status, profileName, environmentName, secretsYMLKeys)
	}

	// Process entries that exist in DB but not in secrets.yml
	for dbPath := range dbEntriesMap {
		if !secretsYMLEntries[dbPath] {
			s.addPathToTree(envNode, dbPath, "extra", profileName, environmentName, secretsYMLKeys)
		}
	}

	root.Children = append(root.Children, envNode)
	return root, nil
}

// addPathToTree adds a path to the tree structure
func (s *service) addPathToTree(parent *TreeNode, path string, status string, profileName string, environmentName string, secretsYMLKeys map[string]map[string]bool) {
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
				IsKey:    false,
				Status:   "",
				Children: []*TreeNode{},
			}

			// Only set status on leaf nodes (entries)
			if isLast {
				child.Status = status

				// Get keys defined in secrets.yml for this entry
				ymlKeys := make(map[string]bool)
				if secretsYMLKeys[path] != nil {
					ymlKeys = secretsYMLKeys[path]
				}

				// If the entry exists in the database, fetch and add its fields as children
				if status == "exists" {
					// Get ALL fields (including empty) to check existence for status
					allDBFields, err := s.keepass.GetAllFieldsByEnvironmentEntry(profileName, environmentName, path)
					if err == nil {
						// Create map of all db fields for status checking
						allDBFieldsMap := make(map[string]bool)
						for _, fieldName := range allDBFields {
							allDBFieldsMap[fieldName] = true
						}

						// Get only fields with values (to show extra fields)
						fieldsWithValue, err := s.keepass.GetFieldsByEnvironmentEntry(profileName, environmentName, path)
						fieldsWithValueMap := make(map[string]bool)
						if err == nil {
							for _, fieldName := range fieldsWithValue {
								fieldsWithValueMap[fieldName] = true
							}
						}

						// Process keys from secrets.yml
						// Show ALL keys from secrets.yml with appropriate status:
						// - "exists": field exists in DB and has value
						// - "missing": field doesn't exist in DB OR exists but is empty
						for keyName := range ymlKeys {
							keyStatus := "missing"
							if fieldsWithValueMap[keyName] {
								keyStatus = "exists"
							}

							keyNode := &TreeNode{
								Name:     "key: " + keyName,
								IsEntry:  false,
								IsKey:    true,
								Status:   keyStatus,
								Children: []*TreeNode{},
							}
							child.Children = append(child.Children, keyNode)
						}

						// Process keys from database that are NOT in secrets.yml (extra)
						// Only show if they have value
						for _, fieldName := range fieldsWithValue {
							if !ymlKeys[fieldName] {
								keyNode := &TreeNode{
									Name:     "key: " + fieldName,
									IsEntry:  false,
									IsKey:    true,
									Status:   "extra",
									Children: []*TreeNode{},
								}
								child.Children = append(child.Children, keyNode)
							}
						}
					}
				} else if status == "missing" {
					// Entry doesn't exist in DB, but keys are defined in secrets.yml
					for keyName := range ymlKeys {
						keyNode := &TreeNode{
							Name:     "key: " + keyName,
							IsEntry:  false,
							IsKey:    true,
							Status:   "missing",
							Children: []*TreeNode{},
						}
						child.Children = append(child.Children, keyNode)
					}
				}
				// Note: if status == "extra", the entry exists in DB but not in secrets.yml
				// In this case, we show all DB fields as "extra"
				if status == "extra" {
					dbFields, err := s.keepass.GetFieldsByEnvironmentEntry(profileName, environmentName, path)
					if err == nil {
						for _, fieldName := range dbFields {
							keyNode := &TreeNode{
								Name:     "key: " + fieldName,
								IsEntry:  false,
								IsKey:    true,
								Status:   "extra",
								Children: []*TreeNode{},
							}
							child.Children = append(child.Children, keyNode)
						}
					}
				}
			}

			current.Children = append(current.Children, child)
		}

		current = child
	}
}

// renderTree prepares the tree structure for the output manager
func (s *service) renderTree(root *TreeNode, outputFormat string) error {
	payload := map[string]interface{}{
		"tree": s.serializeTreeNode(root),
		"_display": map[string]interface{}{
			"format": "tree",
			"style":  outputFormat,
		},
	}

	return s.output.Output(payload, "tree")
}

// serializeTreeNode converts a TreeNode into a map compatible with the output manager
func (s *service) serializeTreeNode(node *TreeNode) map[string]interface{} {
	if node == nil {
		return nil
	}

	children := make([]interface{}, 0, len(node.Children))
	for _, child := range node.Children {
		children = append(children, s.serializeTreeNode(child))
	}

	return map[string]interface{}{
		"name":     node.Name,
		"is_entry": node.IsEntry,
		"is_key":   node.IsKey,
		"status":   node.Status,
		"children": children,
	}
}
