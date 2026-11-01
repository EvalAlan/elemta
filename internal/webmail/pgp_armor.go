package webmail

import (
	"bytes"
	"io"
	"strings"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
)

func armorPublic(w io.Writer, entity *openpgp.Entity) error {
	out, err := armor.Encode(w, openpgp.PublicKeyType, nil)
	if err != nil {
		return err
	}
	if err := entity.Serialize(out); err != nil {
		return err
	}
	return out.Close()
}

// dearmorKey gives the binary form the Web Key Directory serves.
func dearmorKey(armored string) ([]byte, error) {
	block, err := armor.Decode(strings.NewReader(armored))
	if err != nil {
		return nil, err
	}
	var out bytes.Buffer
	_, err = io.Copy(&out, block.Body)
	return out.Bytes(), err
}
