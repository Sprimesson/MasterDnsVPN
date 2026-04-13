package interactive

import (
	"bufio"
	"errors"
	"fmt"
	"masterdnsvpn-go/internal/logger"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
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
	dim     = "\033[2m"
)

func printBanner() {
	fmt.Println(bold + cyan + `
╔═════════════════════════════════════════╗
║        ⚡ MasterDnsVpn + Spr ⚡         ║
║               Welcome!                  ║
╚═════════════════════════════════════════╝` + reset)
	fmt.Println(magenta + "──────────────────────────────────────────" + reset)
	fmt.Println(yellow + "Let's choose the config and resolvers!" + reset)
	fmt.Println(dim + "Type a number and press Enter  •  Ctrl+C to exit" + reset)
	fmt.Println(magenta + "──────────────────────────────────────────" + reset)
}

// pickOne prints a numbered menu and returns the zero-based index of the
// chosen item. Returns an "interrupt" error when stdin is closed or empty.
func pickOne(label string, items []string) (int, error) {
	fmt.Println()
	fmt.Printf("  %s%s%s\n", bold+cyan, label, reset)
	fmt.Println("  " + magenta + strings.Repeat("─", 42) + reset)
	for i, item := range items {
		fmt.Printf("  %s%s%2d%s  %s%s%s\n",
			bold, yellow, i+1, reset,
			green, item, reset)
	}
	fmt.Println("  " + magenta + strings.Repeat("─", 42) + reset)

	reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Printf("  "+bold+cyan+"❯ "+reset+bold+"Enter number (1–%d): "+reset, len(items))
		line, err := reader.ReadString('\n')
		if err != nil {
			fmt.Println()
			return 0, errors.New("interrupt")
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		n, convErr := strconv.Atoi(line)
		if convErr != nil || n < 1 || n > len(items) {
			fmt.Printf("  "+red+"✗ "+reset+"Please enter a number between 1 and %d.\n", len(items))
			continue
		}
		fmt.Printf("  "+green+"✔ "+reset+"Selected: %s%s%s\n", bold, items[n-1], reset)
		return n - 1, nil
	}
}

func RunStartupPicker() (Selection, error) {
	logger.ShouldUseColor() // hack to trigger change of console mode on Windows to enable colors.

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

	configIdx, err := pickOne("Which 'config' do you want to use?", displayNames(configs))
	if err != nil {
		return Selection{ExitRequested: true}, nil
	}

	resolverIdx, err := pickOne(
		"Which list of resolvers do you want to use? (txt files with 'resolver' in name)",
		displayNames(resolvers),
	)
	if err != nil {
		return Selection{ExitRequested: true}, nil
	}

	fmt.Println()

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
