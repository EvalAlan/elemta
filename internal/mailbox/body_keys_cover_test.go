package mailbox

import (
	"context"
	"strings"
	"testing"
)

// A restore drill checks a backup's keys against the backup's metadata:
// every recorded key must be there with the right fingerprint.
func TestCheckBodyKeysCover(t *testing.T) {
	e, _ := isolatedTestEngine(t)
	ctx := context.Background()
	v1, v2, other := "v1:"+b64(1), "v2:"+b64(2), "v1:"+b64(9)
	keys, err := parseBodyKeys(v2 + "," + v1)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.checkBodyKeys(ctx, keys); err != nil {
		t.Fatal(err)
	}
	if err := CheckBodyKeysCover(ctx, e.DB, v2+","+v1); err != nil {
		t.Errorf("the keys in use: %v", err)
	}
	for _, tc := range []struct{ keys, want string }{
		{v2, `key "v1" is missing`},
		{"", `key "v1" is missing`},
		{v2 + "," + other, `key "v1" is not the key`},
	} {
		err := CheckBodyKeysCover(ctx, e.DB, tc.keys)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("keys %q: %v, want %q", tc.keys, err, tc.want)
		}
	}
}
