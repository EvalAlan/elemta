package commands

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/EvalAlan/elemta/internal/dkim"
	"github.com/spf13/cobra"
)

// DKIM key rotation, as commands.
//
// The safe order is: generate a key under a new selector, publish its record,
// wait until `dkim check` confirms DNS serves it, switch the configuration to
// the new selector and key, and only then retire the old selector's record
// (after a few days, so mail signed with it and still in flight verifies).
// Switching before DNS serves the new key fails DKIM on every message, which
// under a DMARC reject policy means receivers refuse the mail.

func init() {
	rootCmd.AddCommand(dkimCmd)
	dkimCmd.AddCommand(dkimKeygenCmd, dkimRecordCmd, dkimCheckCmd)

	dkimKeygenCmd.Flags().StringVar(&dkimDomain, "domain", "", "Signing domain (d=)")
	dkimKeygenCmd.Flags().StringVar(&dkimSelector, "selector", "", "Selector for the new key (s=); use a new one for every rotation")
	dkimKeygenCmd.Flags().StringVar(&dkimKeyType, "type", "rsa", "Key type: rsa or ed25519")
	dkimKeygenCmd.Flags().IntVar(&dkimBits, "bits", 2048, "RSA key size")
	dkimKeygenCmd.Flags().StringVar(&dkimKeyPath, "out", "", "Where to write the private key (must not exist)")

	for _, c := range []*cobra.Command{dkimRecordCmd, dkimCheckCmd} {
		c.Flags().StringVar(&dkimDomain, "domain", "", "Signing domain (d=)")
		c.Flags().StringVar(&dkimSelector, "selector", "", "Selector (s=)")
		c.Flags().StringVar(&dkimKeyPath, "key", "", "Path to the private key")
	}
	for _, c := range []*cobra.Command{dkimKeygenCmd, dkimRecordCmd, dkimCheckCmd} {
		_ = c.MarkFlagRequired("domain")
		_ = c.MarkFlagRequired("selector")
	}
	_ = dkimKeygenCmd.MarkFlagRequired("out")
	_ = dkimRecordCmd.MarkFlagRequired("key")
	_ = dkimCheckCmd.MarkFlagRequired("key")
}

var (
	dkimDomain   string
	dkimSelector string
	dkimKeyType  string
	dkimBits     int
	dkimKeyPath  string

	// dkimLookupTXT is replaced in tests.
	dkimLookupTXT = net.DefaultResolver.LookupTXT
)

var dkimCmd = &cobra.Command{
	Use:   "dkim",
	Short: "Generate, publish and verify DKIM signing keys",
	Long: `Generate, publish and verify DKIM signing keys.

To rotate a key without failing DKIM on any message:

  1. elemta dkim keygen --domain example.com --selector s2026b --out /etc/elemta/dkim/s2026b.key
  2. Publish the printed TXT record in DNS.
  3. elemta dkim check --domain example.com --selector s2026b --key /etc/elemta/dkim/s2026b.key
     and wait until it reports a match.
  4. Point the domain's selector and private_key_path at the new key and restart.
  5. After a few days, remove the old selector's TXT record.`,
	Run: func(cmd *cobra.Command, args []string) { _ = cmd.Help() },
}

var dkimKeygenCmd = &cobra.Command{
	SilenceUsage: true,
	Use:          "keygen",
	Short:        "Generate a new signing key and print its DNS record",
	Args:         cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		key, err := dkim.GenerateKey(dkimKeyType, dkimBits)
		if err != nil {
			return err
		}
		if err := dkim.WritePrivateKey(dkimKeyPath, key); err != nil {
			return err
		}
		fmt.Fprintf(cmd.OutOrStdout(), "Wrote %s key to %s (mode 0600)\n\n", strings.ToLower(dkimKeyType), dkimKeyPath)
		return printDKIMRecord(cmd, key.Public())
	},
}

var dkimRecordCmd = &cobra.Command{
	SilenceUsage: true,
	Use:          "record",
	Short:        "Print the DNS record for an existing key",
	Args:         cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		pub, err := dkim.LoadPublicKey(dkimKeyPath)
		if err != nil {
			return err
		}
		return printDKIMRecord(cmd, pub)
	},
}

var dkimCheckCmd = &cobra.Command{
	SilenceUsage: true,
	Use:          "check",
	Short:        "Confirm DNS publishes the key before switching to it",
	Args:         cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		pub, err := dkim.LoadPublicKey(dkimKeyPath)
		if err != nil {
			return err
		}
		name := dkim.RecordName(dkimSelector, dkimDomain)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		records, err := dkimLookupTXT(ctx, name)
		if err != nil {
			return fmt.Errorf("%s is not published yet (or DNS failed): %w", name, err)
		}
		published, err := dkim.PublishedKey(records)
		if err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		if !dkim.SamePublicKey(pub, published) {
			return fmt.Errorf("%s publishes a different key from %s; do not switch to this selector", name, dkimKeyPath)
		}
		fmt.Fprintf(cmd.OutOrStdout(), "OK: %s publishes the key in %s. It is safe to sign with this selector.\n", name, dkimKeyPath)
		return nil
	},
}

func printDKIMRecord(cmd *cobra.Command, pub interface{}) error {
	record, err := dkim.DNSRecord(pub)
	if err != nil {
		return err
	}
	out := cmd.OutOrStdout()
	fmt.Fprintf(out, "Publish this TXT record:\n\n  Name:  %s\n  Value: %s\n\n", dkim.RecordName(dkimSelector, dkimDomain), record)
	if len(record) > 255 {
		fmt.Fprintln(out, "The value is longer than 255 characters. Most DNS providers split it for you;")
		fmt.Fprintln(out, "in a zone file, write it as several quoted strings in one record.")
	}
	fmt.Fprintf(out, "Then run: elemta dkim check --domain %s --selector %s --key <key file>\n", dkimDomain, dkimSelector)
	return nil
}
