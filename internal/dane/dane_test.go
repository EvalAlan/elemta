package dane

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func makeCert(t *testing.T, cn string, dnsNames []string, isCA bool, parent *x509.Certificate, parentKey *ecdsa.PrivateKey, notAfter time.Time) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: cn},
		DNSNames:              dnsNames,
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              notAfter,
		IsCA:                  isCA,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if parent == nil {
		parent, parentKey = tmpl, key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, parentKey)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c, key
}

func sha256Of(b []byte) []byte { s := sha256.Sum256(b); return s[:] }
func sha512Of(b []byte) []byte { s := sha512.Sum512(b); return s[:] }

func TestVerifyDANEEE(t *testing.T) {
	// Self-signed, wrong name, expired: none of it matters for DANE-EE.
	leaf, _ := makeCert(t, "whatever", []string{"not-the-mx.test"}, false, nil, nil, time.Now().Add(-time.Minute))
	other, _ := makeCert(t, "other", nil, false, nil, nil, time.Now().Add(time.Hour))
	cs := tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf}}

	good := []TLSA{
		{UsageDANEEE, SelectorSPKI, MatchSHA256, sha256Of(leaf.RawSubjectPublicKeyInfo)},
		{UsageDANEEE, SelectorCert, MatchSHA256, sha256Of(leaf.Raw)},
		{UsageDANEEE, SelectorSPKI, MatchSHA512, sha512Of(leaf.RawSubjectPublicKeyInfo)},
		{UsageDANEEE, SelectorCert, MatchFull, leaf.Raw},
	}
	for _, r := range good {
		if err := Verify(cs, []TLSA{r}, "mx.example.com"); err != nil {
			t.Errorf("%s: %v", r, err)
		}
	}
	bad := TLSA{UsageDANEEE, SelectorSPKI, MatchSHA256, sha256Of(other.RawSubjectPublicKeyInfo)}
	if err := Verify(cs, []TLSA{bad}, "mx.example.com"); !errors.Is(err, ErrNoMatch) {
		t.Errorf("non-matching record: %v", err)
	}
	// Any one matching record is enough (key rollover publishes two).
	if err := Verify(cs, []TLSA{bad, good[0]}, "mx.example.com"); err != nil {
		t.Errorf("rollover pair: %v", err)
	}
}

func TestVerifyDANETA(t *testing.T) {
	ca, caKey := makeCert(t, "Private CA", nil, true, nil, nil, time.Now().Add(time.Hour))
	leaf, _ := makeCert(t, "mx", []string{"mx.example.com"}, false, ca, caKey, time.Now().Add(time.Hour))
	cs := tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf, ca}}
	ta := []TLSA{{UsageDANETA, SelectorSPKI, MatchSHA256, sha256Of(ca.RawSubjectPublicKeyInfo)}}

	if err := Verify(cs, ta, "mx.example.com"); err != nil {
		t.Errorf("leaf under TA for the MX name: %v", err)
	}
	// Unlike DANE-EE, DANE-TA checks the name.
	if err := Verify(cs, ta, "other.example.com"); err == nil {
		t.Error("DANE-TA accepted a leaf for the wrong name")
	}
	// The TA must be in the chain the server sent.
	alone := tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf}}
	if err := Verify(alone, ta, "mx.example.com"); err == nil {
		t.Error("DANE-TA matched without the TA in the chain")
	}
}

func TestUsableDropsPKIXUsagesAndUnknownTypes(t *testing.T) {
	in := []TLSA{
		{0, 0, 1, nil}, {1, 1, 1, nil}, // PKIX-TA, PKIX-EE: unusable for SMTP
		{3, 1, 1, nil}, {2, 0, 2, nil},
		{3, 2, 1, nil}, {3, 1, 9, nil}, // unknown selector, matching type
	}
	got := Usable(in)
	if len(got) != 2 || got[0].Usage != 3 || got[1].Usage != 2 {
		t.Errorf("Usable = %v", got)
	}
}

// fakeDNS serves fixed answers, with AD set or not, from a local UDP server.
func fakeDNS(t *testing.T, handler func(q dns.Question) (rcode int, ad bool, answers []dns.RR)) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(req)
		rcode, ad, answers := handler(req.Question[0])
		m.Rcode = rcode
		m.AuthenticatedData = ad
		m.Answer = answers
		_ = w.WriteMsg(m)
	})}
	go func() { _ = srv.ActivateAndServe() }()
	t.Cleanup(func() { _ = srv.Shutdown() })
	return pc.LocalAddr().String()
}

func TestDNSResolver(t *testing.T) {
	digest := sha256Of([]byte("key"))
	addr := fakeDNS(t, func(q dns.Question) (int, bool, []dns.RR) {
		switch q.Name {
		case "signed.test.":
			return dns.RcodeSuccess, true, nil
		case "unsigned.test.":
			return dns.RcodeSuccess, false, nil
		case "broken.test.":
			return dns.RcodeServerFailure, false, nil
		case "_25._tcp.mx.signed.test.":
			return dns.RcodeSuccess, true, []dns.RR{&dns.TLSA{
				Hdr:   dns.RR_Header{Name: q.Name, Rrtype: dns.TypeTLSA, Class: dns.ClassINET, Ttl: 300},
				Usage: 3, Selector: 1, MatchingType: 1, Certificate: hex.EncodeToString(digest),
			}}
		case "_25._tcp.mx.unsigned.test.":
			return dns.RcodeSuccess, false, []dns.RR{&dns.TLSA{
				Hdr:   dns.RR_Header{Name: q.Name, Rrtype: dns.TypeTLSA, Class: dns.ClassINET, Ttl: 300},
				Usage: 3, Selector: 1, MatchingType: 1, Certificate: hex.EncodeToString(digest),
			}}
		}
		return dns.RcodeNameError, true, nil
	})
	r := NewDNSResolver(addr)
	ctx := context.Background()

	if ok, err := r.MXSecure(ctx, "signed.test"); !ok || err != nil {
		t.Errorf("signed MX: %v %v", ok, err)
	}
	if ok, err := r.MXSecure(ctx, "unsigned.test"); ok || err != nil {
		t.Errorf("unsigned MX: %v %v", ok, err)
	}
	if _, err := r.MXSecure(ctx, "broken.test"); !errors.Is(err, ErrBogus) {
		t.Errorf("SERVFAIL: %v, want ErrBogus", err)
	}

	recs, secure, err := r.LookupTLSA(ctx, "mx.signed.test.", 25)
	if err != nil || !secure || len(recs) != 1 || recs[0].String() != "3 1 1 "+hex.EncodeToString(digest) {
		t.Errorf("signed TLSA: %v %v %v", recs, secure, err)
	}
	// Records without AD are not trusted, even if present.
	if recs, secure, err := r.LookupTLSA(ctx, "mx.unsigned.test", 25); secure || len(recs) != 0 || err != nil {
		t.Errorf("unsigned TLSA: %v %v %v", recs, secure, err)
	}
	// Signed proof that there are none.
	if recs, secure, err := r.LookupTLSA(ctx, "mx.none.test", 25); !secure || len(recs) != 0 || err != nil {
		t.Errorf("signed NXDOMAIN: %v %v %v", recs, secure, err)
	}
}
