package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

func main() {
	field := flag.String("field", "", "value to print (tag, commit, dirty, build-time, build-date-short, version)")
	flag.Parse()

	if *field == "" {
		fmt.Fprintln(os.Stderr, "versioninfo: missing --field value")
		os.Exit(1)
	}

	switch strings.ToLower(*field) {
	case "tag":
		fmt.Print(gitTag())
	case "commit":
		fmt.Print(gitCommit())
	case "dirty":
		fmt.Print(gitDirtySuffix())
	case "build-time":
		fmt.Print(buildTime())
	case "build-date-short":
		fmt.Print(buildDateShort())
	case "version":
		fmt.Print(computeVersion())
	default:
		fmt.Fprintf(os.Stderr, "versioninfo: unsupported field %q\n", *field)
		os.Exit(1)
	}
}

func gitTag() string {
	output, err := runGit("describe", "--tags", "--exact-match")
	if err != nil {
		return ""
	}

	tag := strings.TrimSpace(output)
	if tag == "" {
		return ""
	}

	matched, _ := regexp.MatchString(`^v[0-9]+\.[0-9]+\.[0-9]+$`, tag)
	if !matched {
		return ""
	}

	return tag
}

func gitCommit() string {
	output, err := runGit("rev-parse", "--short", "HEAD")
	if err != nil {
		return "unknown"
	}
	commit := strings.TrimSpace(output)
	if commit == "" {
		return "unknown"
	}
	return commit
}

func gitDirtySuffix() string {
	cmd := exec.Command("git", "diff", "--quiet")
	if err := cmd.Run(); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			// Exit code 1 means dirty working tree. Any non-zero exit should mark dirty
			if exitErr.ExitCode() != 0 {
				return "-dirty"
			}
		}
		return "-dirty"
	}
	return ""
}

func buildTime() string {
	return time.Now().UTC().Format(time.RFC3339)
}

func buildDateShort() string {
	return time.Now().UTC().Format("20060102150405")
}

func computeVersion() string {
	tag := gitTag()
	commit := gitCommit()
	dirty := gitDirtySuffix()
	dateShort := buildDateShort()

	if tag != "" {
		return fmt.Sprintf("%s+%s%s", tag, dateShort, dirty)
	}

	return fmt.Sprintf("v0.1.0-dev+%s.%s%s", dateShort, commit, dirty)
}

func runGit(args ...string) (string, error) {
	cmd := exec.Command("git", args...)
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return string(out), nil
}
