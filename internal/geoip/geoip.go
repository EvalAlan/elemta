// Package geoip places an address on a map, for sign-in alerts
// (internal/abuse). It reads the free DB-IP City Lite database, which is
// licensed CC BY 4.0: any page that shows a result must link to DB-IP.com.
package geoip

import (
	"net"
	"os"

	"github.com/oschwald/maxminddb-golang"
)

// PathEnv names the database file. Without it nothing is located, and the
// alerts that need a location don't happen.
const PathEnv = "ELEMTA_GEOIP_DB"

// Place is where an address is, as near as a free database can say: a city
// for most addresses, a country for the rest.
type Place struct {
	Country   string  `json:"country"`
	City      string  `json:"city,omitempty"`
	Latitude  float64 `json:"latitude"`
	Longitude float64 `json:"longitude"`
}

// DB is an open database.
type DB struct {
	reader *maxminddb.Reader
}

// Open opens the database at path. It is mapped into memory rather than read,
// so only the parts lookups touch take memory.
func Open(path string) (*DB, error) {
	reader, err := maxminddb.Open(path)
	if err != nil {
		return nil, err
	}
	return &DB{reader: reader}, nil
}

// FromEnv opens the database PathEnv names. It returns nil and no error when
// the variable isn't set.
func FromEnv() (*DB, error) {
	path := os.Getenv(PathEnv)
	if path == "" {
		return nil, nil
	}
	// #nosec G703 -- the operator's own setting, read once at start; no request reaches it
	if _, err := os.Stat(path); err != nil {
		return nil, err
	}
	return Open(path)
}

// Close releases the database.
func (d *DB) Close() error {
	if d == nil || d.reader == nil {
		return nil
	}
	return d.reader.Close()
}

type record struct {
	City struct {
		Names map[string]string `maxminddb:"names"`
	} `maxminddb:"city"`
	Country struct {
		ISOCode string `maxminddb:"iso_code"`
	} `maxminddb:"country"`
	Location struct {
		Latitude  float64 `maxminddb:"latitude"`
		Longitude float64 `maxminddb:"longitude"`
	} `maxminddb:"location"`
}

// Locate reports where ip is. Private and reserved addresses have no place.
func (d *DB) Locate(ip net.IP) (Place, bool) {
	if d == nil || ip == nil || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() {
		return Place{}, false
	}
	var r record
	if err := d.reader.Lookup(ip, &r); err != nil || r.Country.ISOCode == "" {
		return Place{}, false
	}
	return Place{Country: r.Country.ISOCode, City: r.City.Names["en"], Latitude: r.Location.Latitude, Longitude: r.Location.Longitude}, true
}
