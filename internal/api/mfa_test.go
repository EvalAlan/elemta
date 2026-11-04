package api

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1" // #nosec G505 -- TOTP is HMAC-SHA1
	"encoding/base32"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/EvalAlan/elemta/internal/adminmfa"
	"github.com/EvalAlan/elemta/internal/auth"
	"github.com/stretchr/testify/require"
)

// totpAt is what an authenticator app shows for secret at a time step.
func totpAt(t *testing.T, secret string, step int64) string {
	t.Helper()
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ReplaceAll(secret, " ", ""))
	require.NoError(t, err)
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(step)) // #nosec G115 -- positive
	mac := hmac.New(sha1.New, key)
	mac.Write(msg[:])
	sum := mac.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	return fmt.Sprintf("%06d", (binary.BigEndian.Uint32(sum[off:off+4])&0x7fffffff)%1000000)
}

// post sends JSON with no credentials, as the login page does, and returns
// the status, body and any session cookie set.
func post(t *testing.T, url string, body any) (int, string, string) {
	t.Helper()
	data, err := json.Marshal(body)
	require.NoError(t, err)
	resp, err := http.Post(url, "application/json", bytes.NewReader(data))
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	out, _ := io.ReadAll(resp.Body)
	cookie := ""
	for _, c := range resp.Cookies() {
		if c.Name == "elemta_session" && c.Value != "" {
			cookie = c.Value
		}
	}
	return resp.StatusCode, string(out), cookie
}

func TestConsoleTwoStepSignIn(t *testing.T) {
	base, usersFile := startUserServer(t)
	root := func(method, path string, body any) (int, string) {
		return userRequest(t, method, base+path, "root", testAdminPassword, body)
	}

	// Nothing set up: the password alone signs in, and the page says so.
	code, body := root("GET", "/auth/security", nil)
	require.Equal(t, http.StatusOK, code, body)
	require.JSONEq(t, `{"totp":false,"recovery_left":0,"passkeys":[]}`, body)
	code, body, cookie := post(t, base+"/auth/login", map[string]string{"username": "root", "password": testAdminPassword})
	require.Equal(t, http.StatusOK, code, body)
	require.Contains(t, body, `"status":"success"`)
	require.NotEmpty(t, cookie)

	// Setting up asks for the password again.
	code, _ = root("POST", "/auth/security/totp/begin", map[string]string{"password": "wrong-password-1"})
	require.Equal(t, http.StatusForbidden, code)
	code, body = root("POST", "/auth/security/totp/begin", map[string]string{"password": testAdminPassword})
	require.Equal(t, http.StatusOK, code, body)
	var begun struct{ Secret, URI, QR string }
	require.NoError(t, json.Unmarshal([]byte(body), &begun))
	require.True(t, strings.HasPrefix(begun.QR, "data:image/png;base64,"))
	require.Contains(t, begun.URI, "otpauth://totp/Elemta%20Admin%20%28127.0.0.1%29:root")
	step := time.Now().Unix() / 30
	code, body = root("POST", "/auth/security/totp/confirm", map[string]string{"code": "not-a-code"})
	require.Equal(t, http.StatusBadRequest, code, body)
	code, body = root("POST", "/auth/security/totp/confirm", map[string]string{"code": totpAt(t, begun.Secret, step)})
	require.Equal(t, http.StatusOK, code, body)
	var confirmed struct {
		Recovery []string `json:"recovery_codes"`
	}
	require.NoError(t, json.Unmarshal([]byte(body), &confirmed))
	require.Len(t, confirmed.Recovery, 10)

	// Kept beside the users file, for the console only.
	info, err := os.Stat(adminmfa.PathFor(usersFile))
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o600), info.Mode().Perm())

	// A password on every request can't carry a code.
	code, _ = root("GET", "/auth/me", nil)
	require.Equal(t, http.StatusUnauthorized, code)

	// The password now leads to a second step, with no session yet.
	code, body, cookie = post(t, base+"/auth/login", map[string]string{"username": "root", "password": testAdminPassword})
	require.Equal(t, http.StatusOK, code, body)
	require.Empty(t, cookie, "a session before the second step")
	var pending struct {
		Status, Token string
		Methods       []string
	}
	require.NoError(t, json.Unmarshal([]byte(body), &pending))
	require.Equal(t, "second_factor", pending.Status)
	require.Equal(t, []string{"totp"}, pending.Methods)

	code, _, cookie = post(t, base+"/auth/login/code", map[string]string{"token": pending.Token, "code": "000000"})
	require.Equal(t, http.StatusUnauthorized, code)
	require.Empty(t, cookie)
	code, _, _ = post(t, base+"/auth/login/code", map[string]string{"token": "made-up", "code": totpAt(t, begun.Secret, step+1)})
	require.Equal(t, http.StatusUnauthorized, code)
	// The code used to confirm can't sign in; the next one does.
	code, _, _ = post(t, base+"/auth/login/code", map[string]string{"token": pending.Token, "code": totpAt(t, begun.Secret, step)})
	require.Equal(t, http.StatusUnauthorized, code)
	code, body, cookie = post(t, base+"/auth/login/code", map[string]string{"token": pending.Token, "code": totpAt(t, begun.Secret, step+1)})
	require.Equal(t, http.StatusOK, code, body)
	require.Contains(t, body, `"username":"root"`)
	require.NotEmpty(t, cookie)
	req, _ := http.NewRequest("GET", base+"/auth/me", nil)
	req.AddCookie(&http.Cookie{Name: "elemta_session", Value: cookie})
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	_ = resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	// The token is spent.
	code, _, _ = post(t, base+"/auth/login/code", map[string]string{"token": pending.Token, "code": confirmed.Recovery[0]})
	require.Equal(t, http.StatusUnauthorized, code)

	// A recovery code signs in once.
	_, body, _ = post(t, base+"/auth/login", map[string]string{"username": "root", "password": testAdminPassword})
	require.NoError(t, json.Unmarshal([]byte(body), &pending))
	code, _, cookie = post(t, base+"/auth/login/code", map[string]string{"token": pending.Token, "code": confirmed.Recovery[0]})
	require.Equal(t, http.StatusOK, code)
	require.NotEmpty(t, cookie)
	_, body, _ = post(t, base+"/auth/login", map[string]string{"username": "root", "password": testAdminPassword})
	require.NoError(t, json.Unmarshal([]byte(body), &pending))
	code, _, _ = post(t, base+"/auth/login/code", map[string]string{"token": pending.Token, "code": confirmed.Recovery[0]})
	require.Equal(t, http.StatusUnauthorized, code)

	// Guessing ends the attempt: the token stops working after five.
	for range 4 {
		code, _, _ = post(t, base+"/auth/login/code", map[string]string{"token": pending.Token, "code": "999999"})
		require.Equal(t, http.StatusUnauthorized, code)
	}
	code, body, _ = post(t, base+"/auth/login/code", map[string]string{"token": pending.Token, "code": confirmed.Recovery[1]})
	require.True(t, code == http.StatusUnauthorized || code == http.StatusTooManyRequests, "%d %s", code, body)

	// Another administrator can turn it off for someone locked out; the
	// list shows who has it.
	hash := mustHash(t, testUserPassword)
	appendUser(t, usersFile, "second:"+hash+":admin")
	code, body = userRequest(t, "GET", base+"/api/users", "second", testUserPassword, nil)
	require.Equal(t, http.StatusOK, code, body)
	require.Contains(t, body, `"username":"root","roles":["admin"],"is_admin":true,"two_factor":true`)
	code, body = userRequest(t, "POST", base+"/api/users/root/reset-2fa", "viewer", testUserPassword, nil)
	require.Equal(t, http.StatusForbidden, code, body)
	// Not your own: that needs your password, in your settings.
	code, body = userRequest(t, "POST", base+"/api/users/second/reset-2fa", "second", testUserPassword, nil)
	require.Equal(t, http.StatusConflict, code, body)
	code, body = userRequest(t, "POST", base+"/api/users/root/reset-2fa", "second", testUserPassword, nil)
	require.Equal(t, http.StatusOK, code, body)
	// (root's own sign-in is throttled now, after the guessing above.)
	_, body = userRequest(t, "GET", base+"/api/users", "second", testUserPassword, nil)
	require.Contains(t, body, `"username":"root","roles":["admin"],"is_admin":true,"two_factor":false`)
}

func mustHash(t *testing.T, password string) string {
	t.Helper()
	h, err := auth.HashPassword(password)
	require.NoError(t, err)
	return h
}

func appendUser(t *testing.T, usersFile, line string) {
	t.Helper()
	f, err := os.OpenFile(usersFile, os.O_APPEND|os.O_WRONLY, 0o600) // #nosec G304 -- test file
	require.NoError(t, err)
	_, err = f.WriteString(line + "\n")
	require.NoError(t, err)
	require.NoError(t, f.Close())
	// The users file is re-read when its size or time changes; make sure
	// the change is seen even within the same clock tick.
	later := time.Now().Add(2 * time.Second)
	require.NoError(t, os.Chtimes(usersFile, later, later))
}
