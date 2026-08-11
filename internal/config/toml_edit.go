package config

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// Surgical TOML editing.
//
// Configuration written back from the API used to be rebuilt from
// DefaultConfig() and re-serialised by SaveConfig, which emits only the handful
// of sections it knows about. Everything else in the file — [antivirus],
// [antispam], [tls], [auth], [dkim], top-level settings, and every comment —
// was silently dropped. Toggling the rate limiter in the web UI therefore
// turned off virus and spam scanning and reset queue.backend from sqlite to
// file, which points the server at a different queue and orphans everything
// already in it.
//
// The fix is to stop regenerating the file. These helpers change the keys they
// are asked to change and leave every other byte alone, so a setting this code
// has never heard of survives a write.

// SetTOMLValue sets key to value inside section, returning the updated
// document. An empty section means the top level, above the first [table].
//
// The key is updated in place if present, appended to the section if not, and
// the section is created at the end of the document if it does not exist.
// Comments, ordering and unrelated sections are preserved exactly.
func SetTOMLValue(doc []byte, section, key string, value interface{}) ([]byte, error) {
	formatted, err := formatTOMLValue(value)
	if err != nil {
		return nil, fmt.Errorf("%s.%s: %w", section, key, err)
	}

	lines := strings.Split(string(doc), "\n")
	current := "" // the section each line belongs to
	sectionStart, sectionEnd := -1, -1

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)

		if strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
			// Leaving the target section: everything before this line was ours.
			if current == section && sectionStart >= 0 {
				sectionEnd = i
			}
			current = strings.Trim(trimmed, "[]")
			if current == section {
				sectionStart = i
			}
			continue
		}

		if current != section {
			continue
		}
		if sectionStart < 0 && section == "" {
			sectionStart = 0
		}

		// An existing assignment for this key: replace just its value, keeping
		// any trailing comment on the line.
		if name, ok := tomlAssignmentKey(trimmed); ok && name == key {
			indent := line[:len(line)-len(strings.TrimLeft(line, " \t"))]
			lines[i] = fmt.Sprintf("%s%s = %s%s", indent, key, formatted, tomlTrailingComment(line))
			return []byte(strings.Join(lines, "\n")), nil
		}
	}

	if sectionStart < 0 {
		// No such section: add it, with the key, at the end.
		doc := strings.TrimRight(strings.Join(lines, "\n"), "\n")
		if section == "" {
			return []byte(fmt.Sprintf("%s = %s\n%s\n", key, formatted, doc)), nil
		}
		return []byte(fmt.Sprintf("%s\n\n[%s]\n%s = %s\n", doc, section, key, formatted)), nil
	}

	if sectionEnd < 0 {
		sectionEnd = len(lines)
	}
	// Insert after the last non-blank line of the section, so the key does not
	// land after the blank line that separates it from the next one.
	insert := sectionEnd
	for insert > sectionStart+1 && strings.TrimSpace(lines[insert-1]) == "" {
		insert--
	}

	out := make([]string, 0, len(lines)+1)
	out = append(out, lines[:insert]...)
	out = append(out, fmt.Sprintf("%s = %s", key, formatted))
	out = append(out, lines[insert:]...)
	return []byte(strings.Join(out, "\n")), nil
}

// RemoveTOMLSection removes a table and its descendant tables. It is used only
// for one-way migrations after the replacement plugin tables have already been
// written, so a legacy [dkim] plus [[dkim.domains]] cannot remain beside the
// canonical [plugins.dkim] and make the next reload ambiguous.
func RemoveTOMLSection(doc []byte, section string) []byte {
	lines := strings.Split(string(doc), "\n")
	out := make([]string, 0, len(lines))
	skipping := false
	var pendingComments []string
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
			name := strings.Trim(trimmed, "[]")
			name = strings.TrimSpace(name)
			remove := name == section || strings.HasPrefix(name, section+".")
			if skipping && !remove {
				// Comments immediately before the next table document that table,
				// not the removed one. Hold them while skipping and restore them
				// only when an unrelated table proves they were trailing.
				out = append(out, pendingComments...)
				pendingComments = nil
			}
			skipping = remove
		}
		if !skipping {
			out = append(out, line)
		} else if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			pendingComments = append(pendingComments, line)
		} else {
			pendingComments = nil
		}
	}
	return []byte(strings.Join(out, "\n"))
}

// tomlAssignmentKey returns the key of a "key = value" line, if it is one.
// Comments and section headers are not assignments.
func tomlAssignmentKey(trimmed string) (string, bool) {
	if trimmed == "" || strings.HasPrefix(trimmed, "#") {
		return "", false
	}
	eq := strings.Index(trimmed, "=")
	if eq < 0 {
		return "", false
	}
	name := strings.TrimSpace(trimmed[:eq])
	if name == "" || strings.ContainsAny(name, "[]{}") {
		return "", false
	}
	return strings.Trim(name, `"'`), true
}

// tomlTrailingComment returns the trailing comment on a line, including its
// leading spacing, or "" when there is none. Quoted values may contain '#',
// so the scan tracks quoting.
func tomlTrailingComment(line string) string {
	eq := strings.Index(line, "=")
	if eq < 0 {
		return ""
	}
	inQuote := byte(0)
	for i := eq + 1; i < len(line); i++ {
		c := line[i]
		switch {
		case inQuote != 0:
			if c == inQuote {
				inQuote = 0
			}
		case c == '"' || c == '\'':
			inQuote = c
		case c == '#':
			return " " + strings.TrimSpace(line[i:])
		}
	}
	return ""
}

// formatTOMLValue renders a Go value as TOML. Only the types the API actually
// writes are supported; anything else is an error rather than a guess, because
// guessing here corrupts the file.
func formatTOMLValue(value interface{}) (string, error) {
	switch v := value.(type) {
	case bool:
		return strconv.FormatBool(v), nil
	case string:
		return strconv.Quote(v), nil
	case int:
		return strconv.Itoa(v), nil
	case int64:
		return strconv.FormatInt(v, 10), nil
	case float64:
		// Whole floats render as integers so a count does not become "5.0".
		if v == float64(int64(v)) {
			return strconv.FormatInt(int64(v), 10), nil
		}
		return strconv.FormatFloat(v, 'f', -1, 64), nil
	case []string:
		quoted := make([]string, len(v))
		for i, s := range v {
			quoted[i] = strconv.Quote(s)
		}
		return "[" + strings.Join(quoted, ", ") + "]", nil
	case []map[string]interface{}:
		items := make([]string, 0, len(v))
		for _, item := range v {
			keys := make([]string, 0, len(item))
			for key := range item {
				keys = append(keys, key)
			}
			sort.Strings(keys)
			fields := make([]string, 0, len(keys))
			for _, key := range keys {
				formatted, err := formatTOMLValue(item[key])
				if err != nil {
					return "", fmt.Errorf("inline table %s: %w", key, err)
				}
				fields = append(fields, key+" = "+formatted)
			}
			items = append(items, "{ "+strings.Join(fields, ", ")+" }")
		}
		return "[" + strings.Join(items, ", ") + "]", nil
	default:
		return "", fmt.Errorf("unsupported TOML value type %T", value)
	}
}
