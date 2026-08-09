package commands

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"

	"github.com/busybox42/elemta/internal/auth"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

// The admin API and web UI authenticate against a users file of
// "username:bcrypt-hash" lines, but nothing shipped could write one. Enabling
// authentication therefore meant hand-generating a bcrypt hash, which is enough
// friction that leaving auth off looks like the easier option. These commands
// remove that excuse.

func init() {
	rootCmd.AddCommand(userCmd)
	userCmd.AddCommand(userAddCmd)
	userCmd.AddCommand(userListCmd)
	userCmd.AddCommand(userPasswdCmd)
	userCmd.AddCommand(userRemoveCmd)

	for _, c := range []*cobra.Command{userAddCmd, userListCmd, userPasswdCmd, userRemoveCmd} {
		c.Flags().StringVar(&userFile, "file", "", "Path to the users file (defaults to [api].auth_file)")
	}
	for _, c := range []*cobra.Command{userAddCmd, userPasswdCmd} {
		c.Flags().StringVar(&userPassword, "password", "",
			"Password (prompts on the terminal if omitted; passing it here exposes it to the process list)")
	}
}

var (
	userFile     string
	userPassword string
)

var userCmd = &cobra.Command{
	Use:   "user",
	Short: "Manage API and web interface users",
	Long: `Manage the users file used to authenticate the admin API and web interface.

The file holds one "username:bcrypt-hash" entry per line. Point [api].auth_file
at it and set [api].auth_enabled = true.`,
	Run: func(cmd *cobra.Command, args []string) { _ = cmd.Help() },
}

var userAddCmd = &cobra.Command{
	Use:   "add <username>",
	Short: "Add a user",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		path, err := resolveUserFile()
		if err != nil {
			return err
		}
		users, err := readUsers(path)
		if err != nil {
			return err
		}
		if _, exists := users[args[0]]; exists {
			return fmt.Errorf("user %q already exists; use `user passwd` to change the password", args[0])
		}
		password, err := readPassword(cmd, true)
		if err != nil {
			return err
		}
		hash, err := auth.HashPassword(password)
		if err != nil {
			return fmt.Errorf("hash password: %w", err)
		}
		users[args[0]] = hash
		if err := writeUsers(path, users); err != nil {
			return err
		}
		fmt.Printf("Added %q to %s\n", args[0], path)
		return nil
	},
}

var userPasswdCmd = &cobra.Command{
	Use:   "passwd <username>",
	Short: "Change a user's password",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		path, err := resolveUserFile()
		if err != nil {
			return err
		}
		users, err := readUsers(path)
		if err != nil {
			return err
		}
		if _, exists := users[args[0]]; !exists {
			return fmt.Errorf("user %q does not exist in %s", args[0], path)
		}
		password, err := readPassword(cmd, true)
		if err != nil {
			return err
		}
		hash, err := auth.HashPassword(password)
		if err != nil {
			return fmt.Errorf("hash password: %w", err)
		}
		users[args[0]] = hash
		if err := writeUsers(path, users); err != nil {
			return err
		}
		fmt.Printf("Changed the password for %q\n", args[0])
		return nil
	},
}

var userRemoveCmd = &cobra.Command{
	Use:     "remove <username>",
	Aliases: []string{"rm", "delete"},
	Short:   "Remove a user",
	Args:    cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		path, err := resolveUserFile()
		if err != nil {
			return err
		}
		users, err := readUsers(path)
		if err != nil {
			return err
		}
		if _, exists := users[args[0]]; !exists {
			return fmt.Errorf("user %q does not exist in %s", args[0], path)
		}
		delete(users, args[0])
		if err := writeUsers(path, users); err != nil {
			return err
		}
		fmt.Printf("Removed %q\n", args[0])
		return nil
	},
}

var userListCmd = &cobra.Command{
	Use:   "list",
	Short: "List users",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		path, err := resolveUserFile()
		if err != nil {
			return err
		}
		users, err := readUsers(path)
		if err != nil {
			return err
		}
		if len(users) == 0 {
			fmt.Printf("No users in %s\n", path)
			return nil
		}
		names := make([]string, 0, len(users))
		for name := range users {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			fmt.Println(name)
		}
		return nil
	},
}

// resolveUserFile picks the users file from --file, then the loaded config.
func resolveUserFile() (string, error) {
	if userFile != "" {
		return userFile, nil
	}
	if cfg := GetConfig(); cfg != nil && cfg.API.AuthFile != "" {
		return cfg.API.AuthFile, nil
	}
	return "", fmt.Errorf("no users file: set [api].auth_file in the config or pass --file")
}

// readPassword takes the password from the flag, or prompts twice on a
// terminal. Prompting is preferred: a password passed as an argument is visible
// in the process list and in shell history.
func readPassword(cmd *cobra.Command, confirm bool) (string, error) {
	if userPassword != "" {
		return userPassword, nil
	}
	if !term.IsTerminal(int(syscall.Stdin)) {
		return "", fmt.Errorf("no terminal available to prompt for a password; pass --password")
	}

	fmt.Fprint(cmd.OutOrStdout(), "Password: ")
	first, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Fprintln(cmd.OutOrStdout())
	if err != nil {
		return "", fmt.Errorf("read password: %w", err)
	}
	if len(first) == 0 {
		return "", fmt.Errorf("password must not be empty")
	}
	if !confirm {
		return string(first), nil
	}

	fmt.Fprint(cmd.OutOrStdout(), "Confirm password: ")
	second, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Fprintln(cmd.OutOrStdout())
	if err != nil {
		return "", fmt.Errorf("read password: %w", err)
	}
	if string(first) != string(second) {
		return "", fmt.Errorf("passwords do not match")
	}
	return string(first), nil
}

// readUsers loads the users file. A missing file is an empty set, so `user add`
// can create it.
func readUsers(path string) (map[string]string, error) {
	users := make(map[string]string)

	f, err := os.Open(path) // #nosec G304 -- operator-supplied path, this is a CLI
	if err != nil {
		if os.IsNotExist(err) {
			return users, nil
		}
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		users[parts[0]] = parts[1]
	}
	return users, scanner.Err()
}

// writeUsers rewrites the users file atomically and readable only by its owner:
// it holds password hashes.
func writeUsers(path string, users map[string]string) error {
	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("create %s: %w", dir, err)
		}
	}

	names := make([]string, 0, len(users))
	for name := range users {
		names = append(names, name)
	}
	sort.Strings(names)

	var sb strings.Builder
	sb.WriteString("# Elemta API/web users. One username:bcrypt-hash per line.\n")
	sb.WriteString("# Managed by `elemta user`.\n")
	for _, name := range names {
		sb.WriteString(name)
		sb.WriteString(":")
		sb.WriteString(users[name])
		sb.WriteString("\n")
	}

	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(sb.String()), 0o600); err != nil {
		return fmt.Errorf("write %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("replace %s: %w", path, err)
	}
	return nil
}
