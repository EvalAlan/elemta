package commands

import (
	"bufio"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/EvalAlan/elemta/internal/auth"
	"github.com/EvalAlan/elemta/internal/datasource"
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
	userAddCmd.Flags().StringVar(&userRole, "role", "",
		"Role: admin, operator, user or readonly (default: admin for names containing \"admin\", otherwise user)")
	userCmd.AddCommand(userRoleCmd)
	userRoleCmd.Flags().StringVar(&userFile, "file", "", "Path to the users file (defaults to [api].auth_file)")
	for _, c := range []*cobra.Command{userAddCmd, userPasswdCmd} {
		c.Flags().StringVar(&userPassword, "password", "",
			"Password (prompts on the terminal if omitted; passing it here exposes it to the process list)")
	}
}

var (
	userFile     string
	userPassword string
	userRole     string
)

// userRoles are the built-in roles; see internal/auth/rbac.go.
var userRoles = []string{"admin", "operator", "user", "readonly"}

func checkRole(role string) error {
	for _, r := range userRoles {
		if r == role {
			return nil
		}
	}
	return fmt.Errorf("unknown role %q: use one of %s", role, strings.Join(userRoles, ", "))
}

// A running server re-reads the users file when it changes, so none of these
// commands needs a restart to take effect.

var userCmd = &cobra.Command{
	Use:   "user",
	Short: "Manage API and web interface users",
	Long: `Manage the users file used to authenticate the admin API and web interface.

The file holds one "username:bcrypt-hash:role" entry per line. Point
[api].auth_file at it and set [api].auth_enabled = true. A running server picks
up changes on its next request; the dashboard's Users page edits the same file.`,
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
		roles := datasource.LegacyRolesFor(args[0])
		if userRole != "" {
			if err := checkRole(userRole); err != nil {
				return err
			}
			roles = []string{userRole}
		}
		password, err := readPassword(cmd, true)
		if err != nil {
			return err
		}
		if err := auth.ValidatePassword(password); err != nil {
			return err
		}
		hash, err := auth.HashPassword(password)
		if err != nil {
			return fmt.Errorf("hash password: %w", err)
		}
		if err := datasource.ModifyUsersFile(path, func(users map[string]datasource.FileUser) error {
			if _, exists := users[args[0]]; exists {
				return fmt.Errorf("user %q already exists; use `user passwd` to change the password", args[0])
			}
			users[args[0]] = datasource.FileUser{Hash: hash, Roles: roles}
			return nil
		}); err != nil {
			return err
		}
		fmt.Printf("Added %q (%s) to %s\n", args[0], strings.Join(roles, ","), path)
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
		password, err := readPassword(cmd, true)
		if err != nil {
			return err
		}
		if err := auth.ValidatePassword(password); err != nil {
			return err
		}
		hash, err := auth.HashPassword(password)
		if err != nil {
			return fmt.Errorf("hash password: %w", err)
		}
		if err := datasource.ModifyUsersFile(path, func(users map[string]datasource.FileUser) error {
			existing, exists := users[args[0]]
			if !exists {
				return fmt.Errorf("user %q does not exist in %s", args[0], path)
			}
			existing.Hash = hash
			users[args[0]] = existing
			return nil
		}); err != nil {
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
		if err := datasource.ModifyUsersFile(path, func(users map[string]datasource.FileUser) error {
			if _, exists := users[args[0]]; !exists {
				return fmt.Errorf("user %q does not exist in %s", args[0], path)
			}
			delete(users, args[0])
			return nil
		}); err != nil {
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
			fmt.Printf("%s\t%s\n", name, strings.Join(users[name].EffectiveRoles(name), ","))
		}
		return nil
	},
}

var userRoleCmd = &cobra.Command{
	Use:   "role <username> <role>",
	Short: "Set a user's role (admin, operator, user or readonly)",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := checkRole(args[1]); err != nil {
			return err
		}
		path, err := resolveUserFile()
		if err != nil {
			return err
		}
		if err := datasource.ModifyUsersFile(path, func(users map[string]datasource.FileUser) error {
			u, exists := users[args[0]]
			if !exists {
				return fmt.Errorf("user %q does not exist in %s", args[0], path)
			}
			u.Roles = []string{args[1]}
			users[args[0]] = u
			return nil
		}); err != nil {
			return err
		}
		fmt.Printf("%q is now %s\n", args[0], args[1])
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
	// Not a terminal: read one line from stdin. This is what lets a setup
	// script pipe a password in without putting it on the command line, where
	// it would be visible in the process list and in shell history — the same
	// reason prompting is preferred over --password interactively.
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		line, err := bufio.NewReader(os.Stdin).ReadString('\n')
		password := strings.TrimRight(line, "\r\n")
		if password == "" {
			if err != nil {
				return "", fmt.Errorf("no terminal available and no password on stdin: %w", err)
			}
			return "", fmt.Errorf("password must not be empty")
		}
		return password, nil
	}

	fmt.Fprint(cmd.OutOrStdout(), "Password: ")
	first, err := term.ReadPassword(int(os.Stdin.Fd()))
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
	second, err := term.ReadPassword(int(os.Stdin.Fd()))
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
func readUsers(path string) (map[string]datasource.FileUser, error) {
	return datasource.ReadUsersFile(path)
}
