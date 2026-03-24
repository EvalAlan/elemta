package runtimepaths

import "os"

// Profile describes the default path model Elemta should prefer.
type Profile struct {
	QueueDir      string
	PluginsDir    string
	LogDir        string
	LogFile       string
	AuthSQLiteDB  string
	AuthUsersFile string
}

// Detect returns the preferred default runtime paths for the current
// environment.
func Detect() Profile {
	if isContainerRuntime() {
		return Profile{
			QueueDir:      "/app/queue",
			PluginsDir:    "/app/plugins",
			LogDir:        "/app/logs",
			LogFile:       "/app/logs/elemta.log",
			AuthSQLiteDB:  "/app/config/auth.db",
			AuthUsersFile: "/app/config/users.txt",
		}
	}

	return Profile{
		QueueDir:      "/var/spool/elemta",
		PluginsDir:    "/var/lib/elemta/plugins",
		LogDir:        "/var/log/elemta",
		LogFile:       "/var/log/elemta/elemta.log",
		AuthSQLiteDB:  "/var/lib/elemta/auth.db",
		AuthUsersFile: "/etc/elemta/users.txt",
	}
}

func isContainerRuntime() bool {
	if os.Getenv("ELEMTA_CONTAINER") == "1" || os.Getenv("ELEMTA_CONTAINER") == "true" {
		return true
	}

	if exe, err := os.Executable(); err == nil {
		if len(exe) >= 5 && exe[:5] == "/app/" {
			return true
		}
	}

	return false
}
