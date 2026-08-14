package commands

import (
	"reflect"
	"testing"

	"github.com/busybox42/elemta/internal/config"
)

// Fields of api.MainConfig that convertToAPIMainConfig deliberately leaves
// alone, with the reason. Anything not listed here must be populated.
var apiFieldsIntentionallyUnmapped = map[string]string{
	"RateLimiterPluginConfig": "attached later, from the plugin config",
	"SPF":                     "attached later, from the plugin config",
	"DKIM":                    "attached later, from the plugin config",
	"DMARC":                   "attached later, from the plugin config",
	"ARC":                     "attached later, from the plugin config",
	"TLS":                     "attached later, from the TLS config",
	"API":                     "the API server is configured separately",
}

// TestConvertToAPIMainConfig_AllFieldsMapped is the guard rail for a bug this
// conversion has produced three times in one feature: a field added to
// api.MainConfig that nobody remembers to populate here, so it silently holds
// its zero value and the web UI reports a default instead of what is in the
// config file.
//
// The last one was queue_retain_tombstone_body. The setting saved to disk
// correctly and the checkbox still came back checked after a restart, because
// the API never read the file value at all.
//
// internal/config has the same guard for ToSMTPConfig. This conversion had
// none.
func TestConvertToAPIMainConfig_AllFieldsMapped(t *testing.T) {
	cfg := &config.Config{}
	populate(reflect.ValueOf(cfg).Elem())

	out := convertToAPIMainConfig(cfg)

	v := reflect.ValueOf(*out)
	typ := v.Type()
	for i := 0; i < typ.NumField(); i++ {
		name := typ.Field(i).Name
		if !typ.Field(i).IsExported() {
			continue
		}
		if reason, ok := apiFieldsIntentionallyUnmapped[name]; ok {
			t.Logf("skipping %s: %s", name, reason)
			continue
		}
		if v.Field(i).IsZero() {
			t.Errorf("api.MainConfig.%s is zero after convertToAPIMainConfig — the "+
				"web UI will report a default instead of the configured value. "+
				"Populate it there, or add it to apiFieldsIntentionallyUnmapped with a reason.", name)
		}
	}
}

// populate sets every field it can reach to a non-zero value, so the check
// above is really asking "did the conversion carry this across" rather than
// "did the fixture happen to set it".
func populate(v reflect.Value) {
	switch v.Kind() {
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			if v.Type().Field(i).IsExported() {
				populate(v.Field(i))
			}
		}
	case reflect.Ptr:
		if v.IsNil() && v.CanSet() {
			v.Set(reflect.New(v.Type().Elem()))
		}
		if !v.IsNil() {
			populate(v.Elem())
		}
	case reflect.String:
		if v.CanSet() && v.String() == "" {
			v.SetString("set")
		}
	case reflect.Bool:
		if v.CanSet() {
			v.SetBool(true)
		}
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		if v.CanSet() && v.Int() == 0 {
			v.SetInt(7)
		}
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		if v.CanSet() && v.Uint() == 0 {
			v.SetUint(7)
		}
	case reflect.Float32, reflect.Float64:
		if v.CanSet() && v.Float() == 0 {
			v.SetFloat(7)
		}
	case reflect.Slice:
		if v.CanSet() && v.Len() == 0 {
			elem := reflect.New(v.Type().Elem()).Elem()
			populate(elem)
			v.Set(reflect.Append(v, elem))
		}
	case reflect.Map:
		if v.CanSet() && v.IsNil() {
			v.Set(reflect.MakeMap(v.Type()))
		}
	}
}
