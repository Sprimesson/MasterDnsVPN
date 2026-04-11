package interactive

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/manifoldco/promptui"
)

type Selection struct {
	ConfigPath    string
	ResolverPath  string
	ExitRequested bool
}

const (
	reset = "\033[0m"
	bold  = "\033[1m"

	red     = "\033[31m"
	green   = "\033[32m"
	yellow  = "\033[33m"
	blue    = "\033[34m"
	cyan    = "\033[36m"
	magenta = "\033[35m"
)

func printBanner() {
	fmt.Println(bold + cyan + `
╔═════════════════════════════════════════╗
║        ⚡ MasterDnsVpn + Spr ⚡         ║
║               Welcome!                  ║
╚═════════════════════════════════════════╝` + reset)
	fmt.Println(magenta + "──────────────────────────────────────────" + reset)
	fmt.Println(yellow + "Let's choose the config and resolvers!" + reset)
	fmt.Println(yellow + "↑↓ Navigate • Enter Select • Ctrl+C Exit" + reset)
	fmt.Println(magenta + "──────────────────────────────────────────" + reset)
}

func RunStartupPicker() (Selection, error) {
	baseDir, err := executableDir()
	if err != nil {
		return Selection{}, err
	}

	configs, err := findMatchingFiles(baseDir, func(name string) bool {
		n := strings.ToLower(name)
		return strings.Contains(n, "client_config") && strings.HasSuffix(n, ".toml")
	})
	if err != nil {
		return Selection{}, err
	}

	resolvers, err := findMatchingFiles(baseDir, func(name string) bool {
		n := strings.ToLower(name)
		return strings.Contains(n, "resolver") && strings.HasSuffix(n, ".txt")
	})
	if err != nil {
		return Selection{}, err
	}

	if len(configs) == 0 {
		return Selection{}, errors.New(`no "*client_config*.toml" files found in executable directory`)
	}
	if len(resolvers) == 0 {
		return Selection{}, errors.New(`no "*resolver*.txt" files found in executable directory`)
	}

	printBanner()

	configIdx, _, err := (&promptui.Select{
		Label: "Which 'config' do you want to use?",
		Items: displayNames(configs),
		Size:  12,
	}).Run()
	if err != nil {
		if isUserAbort(err) {
			return Selection{ExitRequested: true}, nil
		}
		return Selection{}, err
	}

	resolverIdx, _, err := (&promptui.Select{
		Label: "Which list of resolvers do you want to use? (These txt files have 'resolver' in their names)",
		Items: displayNames(resolvers),
		Size:  12,
	}).Run()
	if err != nil {
		if isUserAbort(err) {
			return Selection{ExitRequested: true}, nil
		}
		return Selection{}, err
	}

	println()

	return Selection{
		ConfigPath:   configs[configIdx],
		ResolverPath: resolvers[resolverIdx],
	}, nil
}

func executableDir() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	return filepath.Dir(exe), nil
}

func findMatchingFiles(dir string, match func(name string) bool) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}

	var out []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if match(e.Name()) {
			out = append(out, filepath.Join(dir, e.Name()))
		}
	}

	sort.Slice(out, func(i, j int) bool {
		return strings.ToLower(filepath.Base(out[i])) < strings.ToLower(filepath.Base(out[j]))
	})

	return out, nil
}

func displayNames(paths []string) []string {
	out := make([]string, len(paths))
	for i, p := range paths {
		out[i] = filepath.Base(p)
	}
	return out
}

func isUserAbort(err error) bool {
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "interrupt") || strings.Contains(s, "cancel")
}
