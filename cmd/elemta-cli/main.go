// Command elemta-cli is the command line interface to a running Elemta server.
//
// Everything it can do lives in the commands package. This file used to be a
// hardcoded switch that printed invented values — "Server: Running", "Active: 0"
// — without contacting anything, while the real cobra tree beside it was never
// imported and so never ran.
package main

import "github.com/EvalAlan/elemta/cmd/elemta-cli/commands"

func main() {
	commands.Execute()
}
