package commands

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/EvalAlan/elemta/internal/webmail"
	"github.com/spf13/cobra"
)

var webmailListen string

var webmailCmd = &cobra.Command{
	Use:   "webmail",
	Short: "Start the webmail",
	Long: `Start Elemta's webmail. It reads mailboxes over IMAP and sends through
Elemta's submission listener, both configured in the [webmail] table.
It keeps no mail of its own, so any number of instances can run side by side.`,
	RunE: runWebmail,
}

func init() {
	rootCmd.AddCommand(webmailCmd)
	webmailCmd.AddCommand(webmailResetCmd)
	webmailCmd.Flags().StringVar(&webmailListen, "listen", "", "HTTP listen address (overrides [webmail].listen)")
}

func runWebmail(cmd *cobra.Command, args []string) error {
	var wc webmail.Config
	if c := GetConfig(); c != nil && c.Webmail != nil {
		wc = *c.Webmail
	}
	if webmailListen != "" {
		wc.Listen = webmailListen
	}
	wc = wc.WithDefaults()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	srv, err := webmail.NewServer(wc, nil, nil, logger)
	if err != nil {
		return fmt.Errorf("webmail: %w (configure the [webmail] table)", err)
	}
	defer srv.Close()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go srv.Sessions().Run(ctx)

	httpSrv := &http.Server{
		Addr:              wc.Listen,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       5 * time.Minute, // uploads of large attachments
		WriteTimeout:      5 * time.Minute,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    64 << 10,
	}
	errc := make(chan error, 1)
	go func() {
		logger.Info("webmail: listening", "addr", wc.Listen, "imap", wc.IMAPAddr, "submission", wc.SubmissionAddr)
		errc <- httpSrv.ListenAndServe()
	}()

	select {
	case err := <-errc:
		if !errors.Is(err, http.ErrServerClosed) {
			return fmt.Errorf("webmail: %w", err)
		}
		return nil
	case <-ctx.Done():
	}
	logger.Info("webmail: shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	return httpSrv.Shutdown(shutdownCtx)
}

var webmailResetCmd = &cobra.Command{
	Use:   "reset-password <email>",
	Short: "Reset a mailbox password as a directory administrator",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		var cfg webmail.Config
		if c := GetConfig(); c != nil && c.Webmail != nil {
			cfg = *c.Webmail
		}
		if cfg.WithDefaults().SessionStore != "valkey" {
			return errors.New("webmail: administrator reset requires Valkey sessions to revoke existing sign-ins")
		}
		srv, err := webmail.NewServer(cfg, nil, nil, nil)
		if err != nil {
			return err
		}
		password, err := readPassword(cmd, true)
		if err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(cmd.Context(), 30*time.Second)
		defer cancel()
		if err := srv.AdminResetPassword(ctx, args[0], password); err != nil {
			return err
		}
		fmt.Fprintf(cmd.OutOrStdout(), "Password reset for %s. Webmail sessions ended.\n", args[0])
		return nil
	},
}
