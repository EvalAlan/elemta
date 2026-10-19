package mailbox

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"net"
	"net/textproto"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/EvalAlan/elemta/internal/mailpolicy"
	"github.com/google/uuid"
)

// POP sessions retain their own numbering and deletion marks. The shared lease
// excludes a second POP client on either replica without reserving a database
// connection for every idle socket. IMAP retains its independent UID view.
// errPOPInUse means another POP session, on this replica or another, holds
// the account's lease (RFC 2449 IN-USE), as opposed to bad credentials.
var errPOPInUse = errors.New("maildrop in use")

type popSession struct {
	s         *Service
	conn      net.Conn
	reader    *bufio.Reader
	writer    *bufio.Writer
	encrypted bool
	user      string
	account   Account
	password  string
	checkedAt time.Time
	folder    Folder
	messages  []Message
	deleted   map[int]bool
	owner     string
}

func (s *Service) servePOP3(ln net.Listener) error {
	var wg sync.WaitGroup
	defer wg.Wait()
	for {
		conn, err := ln.Accept()
		if err != nil {
			return err
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx, cancel := context.WithCancel(s.ctx)
			defer cancel()
			go func() { <-ctx.Done(); _ = conn.Close() }()
			p := &popSession{s: s, conn: conn, reader: bufio.NewReaderSize(conn, 4096), writer: bufio.NewWriter(conn), deleted: make(map[int]bool)}
			defer func() { _ = p.conn.Close(); p.release() }()
			p.run(ctx)
		}()
	}
}
func (p *popSession) line(format string, args ...any) error {
	if _, err := fmt.Fprintf(p.writer, format+"\r\n", args...); err != nil {
		return err
	}
	return p.writer.Flush()
}
func (p *popSession) release() {
	if p.owner == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, _ = p.s.engine.DB.ExecContext(ctx, `DELETE FROM mailbox_pop3_leases WHERE account=$1 AND owner=$2`, p.account.ID, p.owner)
}
func (p *popSession) renew(ctx context.Context) bool {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	result, err := p.s.engine.DB.ExecContext(ctx, `UPDATE mailbox_pop3_leases SET expires=now()+interval '15 minutes' WHERE account=$1 AND owner=$2 AND expires>now()`, p.account.ID, p.owner)
	if err != nil {
		return false
	}
	n, err := result.RowsAffected()
	return err == nil && n == 1
}
func (p *popSession) login(ctx context.Context, password string) error {
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	a, err := p.s.login(ctx, p.user, password, true, mailpolicy.POP3)
	if err != nil {
		return err
	}
	owner := uuid.NewString()
	var got string
	err = p.s.engine.DB.QueryRowContext(ctx, `INSERT INTO mailbox_pop3_leases(account,owner,expires) VALUES($1,$2,now()+interval '15 minutes') ON CONFLICT(account) DO UPDATE SET owner=excluded.owner,expires=excluded.expires WHERE mailbox_pop3_leases.expires<now() RETURNING owner`, a.ID, owner).Scan(&got)
	if errors.Is(err, sql.ErrNoRows) {
		return errPOPInUse
	}
	if err != nil {
		return err
	}
	p.account = a
	p.password = password
	p.checkedAt = time.Now()
	p.owner = owner
	p.folder, p.messages, err = p.s.engine.Snapshot(ctx, a.ID, "INBOX")
	return err
}
func (p *popSession) run(ctx context.Context) {
	if p.line("+OK Elemta POP3 ready; STLS required") != nil {
		return
	}
	failures := 0
	for {
		_ = p.conn.SetDeadline(time.Now().Add(10 * time.Minute))
		raw, err := p.reader.ReadSlice('\n')
		if err != nil {
			return
		}
		if len(raw) > 512 || !bytes.HasSuffix(raw, []byte("\r\n")) {
			_ = p.line("-ERR Invalid command framing")
			return
		}
		raw = raw[:len(raw)-2]
		if bytes.IndexFunc(raw, func(r rune) bool { return r < 32 || r == 127 }) >= 0 {
			_ = p.line("-ERR Invalid command")
			return
		}
		cmd, arg, _ := strings.Cut(string(raw), " ")
		cmd = strings.ToUpper(cmd)
		if p.owner != "" && !p.renew(ctx) {
			_ = p.line("-ERR Maildrop lease unavailable")
			return
		}
		if p.owner != "" && time.Since(p.checkedAt) >= 30*time.Second {
			a, err := p.s.login(ctx, p.user, p.password, true, mailpolicy.POP3)
			if err != nil || a.ID != p.account.ID {
				_ = p.line("-ERR Account credentials have changed")
				return
			}
			p.checkedAt = time.Now()
		}
		if cmd == "QUIT" {
			if arg != "" {
				_ = p.line("-ERR Invalid arguments")
				continue
			}
			if p.owner != "" {
				var uids []uint32
				for i := range p.deleted {
					uids = append(uids, p.messages[i-1].UID)
				}
				if len(uids) > 0 {
					if _, err := p.s.engine.expunge(ctx, p.account.ID, "INBOX", uids, false, p.owner); err != nil {
						_ = p.line("-ERR Unable to commit deletions")
						return
					}
				}
			}
			_ = p.line("+OK Goodbye")
			return
		}
		if cmd == "CAPA" {
			if arg != "" {
				_ = p.line("-ERR Invalid arguments")
				continue
			}
			if p.line("+OK Capabilities") != nil {
				return
			}
			// AUTH-RESP-CODE (RFC 3206) is what entitles the [AUTH] code below.
			caps := []string{"TOP", "UIDL", "RESP-CODES", "AUTH-RESP-CODE"}
			if p.encrypted {
				caps = append(caps, "USER")
			} else if p.s.tlsConfig != nil {
				caps = append(caps, "STLS")
			}
			for _, capability := range caps {
				if p.line("%s", capability) != nil {
					return
				}
			}
			if p.line(".") != nil {
				return
			}
			continue
		}
		if cmd == "STLS" {
			if arg != "" || p.encrypted || p.owner != "" || p.s.tlsConfig == nil {
				_ = p.line("-ERR STLS unavailable")
				continue
			}
			// Discarding buffered cleartext would allow commands to cross the TLS
			// boundary. Refuse pipelined bytes instead of interpreting them as TLS.
			if p.reader.Buffered() != 0 {
				_ = p.line("-ERR STLS cannot be pipelined")
				return
			}
			if p.line("+OK Begin TLS") != nil {
				return
			}
			secured := tls.Server(p.conn, p.s.tlsConfig)
			handshake, cancel := context.WithTimeout(ctx, 15*time.Second)
			err = secured.HandshakeContext(handshake)
			cancel()
			if err != nil {
				return
			}
			p.conn = secured
			p.reader = bufio.NewReaderSize(secured, 4096)
			p.writer = bufio.NewWriter(secured)
			p.encrypted = true
			p.user = ""
			continue
		}
		if !p.encrypted {
			_ = p.line("-ERR [AUTH] Use STLS before authentication")
			continue
		}
		if p.owner == "" {
			switch cmd {
			case "USER":
				if arg == "" || strings.Contains(arg, " ") {
					_ = p.line("-ERR Invalid username")
					continue
				}
				p.user = arg
				_ = p.line("+OK Send password")
			case "PASS":
				if p.user == "" {
					_ = p.line("-ERR Send USER first")
					continue
				}
				if err := p.login(ctx, arg); err != nil {
					if errors.Is(err, errPOPInUse) {
						// Valid credentials: say so, so the client retries later
						// instead of asking the user for a new password.
						_ = p.line("-ERR [IN-USE] Maildrop already locked")
						return
					}
					if errors.Is(err, ErrProtocolDisabled) {
						_ = p.line("-ERR [SYS/PERM] POP3 access is turned off for this account")
						return
					}
					_ = p.line("-ERR [AUTH] Authentication failed")
					failures++
					if p.owner != "" || failures >= 3 {
						return
					}
					p.user = ""
					continue
				}
				_ = p.line("+OK Maildrop ready")
			default:
				_ = p.line("-ERR Authentication required")
			}
			continue
		}
		if err := p.transaction(ctx, cmd, arg); err != nil {
			return
		}
	}
}
func (p *popSession) transaction(ctx context.Context, cmd, arg string) error {
	switch cmd {
	case "STAT", "RSET", "NOOP":
		if arg != "" {
			return p.line("-ERR Invalid arguments")
		}
		if cmd == "RSET" {
			clear(p.deleted)
		}
		if cmd == "NOOP" {
			return p.line("+OK")
		}
		count := 0
		var size int64
		for i, m := range p.messages {
			if !p.deleted[i+1] {
				count++
				size += m.Size
			}
		}
		return p.line("+OK %d %d", count, size)
	case "LIST", "UIDL":
		if arg == "" {
			if err := p.line("+OK Messages"); err != nil {
				return err
			}
			for i, m := range p.messages {
				if !p.deleted[i+1] {
					if err := p.listLine(cmd, i+1, m); err != nil {
						return err
					}
				}
			}
			return p.line(".")
		}
		n, err := strconv.Atoi(arg)
		if err != nil || n < 1 || n > len(p.messages) || p.deleted[n] {
			return p.line("-ERR No such message")
		}
		if cmd == "UIDL" {
			return p.line("+OK %d %d.%d", n, p.folder.Validity, p.messages[n-1].UID)
		}
		return p.line("+OK %d %d", n, p.messages[n-1].Size)
	case "DELE", "RETR", "TOP":
		parts := strings.Split(arg, " ")
		want := 1
		if cmd == "TOP" {
			want = 2
		}
		if len(parts) != want {
			return p.line("-ERR Invalid arguments")
		}
		n, err := strconv.Atoi(parts[0])
		if err != nil || n < 1 || n > len(p.messages) || p.deleted[n] {
			return p.line("-ERR No such message")
		}
		if cmd == "DELE" {
			p.deleted[n] = true
			return p.line("+OK Marked")
		}
		lines := -1
		if cmd == "TOP" {
			lines, err = strconv.Atoi(parts[1])
			if err != nil || lines < 0 {
				return p.line("-ERR Invalid line count")
			}
		}
		release, err := p.s.receiveSlot(ctx)
		if err != nil {
			return p.line("-ERR Maildrop unavailable")
		}
		defer release()
		raw, err := p.s.engine.Read(ctx, p.messages[n-1])
		if err != nil {
			return p.line("-ERR Message unavailable")
		}
		if err = p.line("+OK Message follows"); err != nil {
			return err
		}
		w := textproto.NewWriter(p.writer).DotWriter()
		if lines >= 0 {
			raw = popTop(raw, lines)
		}
		if _, err = w.Write(raw); err != nil {
			return err
		}
		if err = w.Close(); err != nil {
			return err
		}
		return p.writer.Flush()
	default:
		return p.line("-ERR Unknown command")
	}
}
func (p *popSession) listLine(cmd string, n int, m Message) error {
	if cmd == "UIDL" {
		return p.line("%d %d.%d", n, p.folder.Validity, m.UID)
	}
	return p.line("%d %d", n, m.Size)
}
func popTop(raw []byte, n int) []byte {
	reader := bufio.NewReader(bytes.NewReader(raw))
	var out bytes.Buffer
	body := false
	for {
		line, err := reader.ReadBytes('\n')
		if len(line) == 0 && errors.Is(err, io.EOF) {
			break
		}
		if body {
			if n == 0 {
				break
			}
			n--
		}
		out.Write(line)
		if bytes.Equal(line, []byte("\r\n")) || bytes.Equal(line, []byte("\n")) {
			body = true
		}
		if err != nil {
			break
		}
	}
	return out.Bytes()
}
