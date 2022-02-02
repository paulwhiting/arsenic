package cmd

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"

	"github.com/analog-substance/arsenic/lib/util"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var validWordlistTypes []string

// wordlistCmd represents the wordlist command
var wordlistCmd = &cobra.Command{
	Use:   "wordlist",
	Short: "Generate a wordlist",
	Long:  `Generate a wordlist`,
	// ValidArgs: validWordlistTypes,
	ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return getValidWordlistTypes(), cobra.ShellCompDirectiveDefault
	},
	Args: func(cmd *cobra.Command, args []string) error {
		if err := cobra.ExactArgs(1)(cmd, args); err != nil {
			return err
		}
		if !isValidWordlistType(args[0]) {
			return fmt.Errorf("invalid argument %q for %q", args[0], cmd.CommandPath())
		}
		return nil
	},
	Run: func(cmd *cobra.Command, args []string) {
		generateWordlist(args[0])
	},
}

func getValidWordlistTypes() []string {
	if len(validWordlistTypes) == 0 {
		wordlistsMap := viper.GetStringMap("wordlists")
		for wordlist := range wordlistsMap {
			validWordlistTypes = append(validWordlistTypes, wordlist)
		}
		sort.Strings(validWordlistTypes)
	}

	return validWordlistTypes
}

func generateWordlist(wordlistType string) {
	lineMap := make(map[string]bool)
	lines := []string{}

	for _, wordlistPath := range util.GetWordlists(wordlistType) {
		file, err := os.Open(wordlistPath)
		if err != nil {
			return
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			rawLine := scanner.Text()

			if shouldIgnoreLine(wordlistType, rawLine) {
				continue
			}

			line := cleanLine(wordlistType, rawLine)
			if _, ok := lineMap[line]; !ok {
				lines = append(lines, line)
			}
			lineMap[line] = true
		}
	}

	sort.Strings(lines)
	for _, line := range lines {
		fmt.Println(line)
	}
}

func cleanLine(wordlistType, line string) string {
	if wordlistType == "web-content" {
		re := regexp.MustCompile(`^(/+)`)
		line = re.ReplaceAllString(line, "")
	} else if wordlistType == "subdomains" {
		re := regexp.MustCompile(`^\*\.`)
		line = re.ReplaceAllString(line, "")
		line = strings.ToLower(line)
	}
	return strings.TrimSpace(line)
}

func shouldIgnoreLine(wordlistType, line string) bool {
	if isValidWordlistType(wordlistType) {
		// this is why we can't have nice things
		re := regexp.MustCompile(`^(## Contribed by)|^/*(\?|\.$|#!?)|\.(gif|ico|jpe?g|png|js|css)$|^\^|\[[0-9a-zA-Z]\-[0-9a-zA-Z]\]|\*\.|\$$`)
		return re.MatchString(line)
	}
	return false
}

func isValidWordlistType(wordlistType string) bool {
	wordlistTypes := getValidWordlistTypes()
	for _, validType := range wordlistTypes {
		if wordlistType == validType {
			return true
		}
	}
	return false
}

func init() {
	rootCmd.AddCommand(wordlistCmd)

	oldUsage := wordlistCmd.UsageFunc()
	wordlistCmd.SetUsageFunc(func(c *cobra.Command) error {
		c.Use = fmt.Sprintf("wordlist (%s)", strings.Join(getValidWordlistTypes(), "|"))
		return oldUsage(c)
	})

	oldHelp := wordlistCmd.HelpFunc()
	wordlistCmd.SetHelpFunc(func(c *cobra.Command, s []string) {
		if !configInitialized {
			initConfig()
		}

		c.Use = fmt.Sprintf("wordlist (%s)", strings.Join(getValidWordlistTypes(), "|"))
		oldHelp(c, s)
	})
}
