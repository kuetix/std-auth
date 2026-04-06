package main

import (
	"flag"
	"fmt"
	"os"

	stdAuthModules "github.com/kuetix/std-auth/modules"
	stdCoreModules "github.com/kuetix/std-core/modules"

	"github.com/kuetix/engine"
	"github.com/kuetix/engine/boot"
	engineModule "github.com/kuetix/engine/modules"
	"github.com/kuetix/engine/pkg/domain"
)

var Version string
var BuildTime string

func main() {
	if len(os.Args) < 2 {
		fmt.Printf("Usage: %s <workflow_name> -[v|verbose]\n", os.Args[0])
		os.Exit(1)
	}

	workflow := os.Args[1]
	os.Args = os.Args[1:]
	verbose := flag.Bool("verbose", false, "Verbose mode")
	vFlag := flag.Bool("v", false, "Verbose mode")
	flag.Parse()

	engineModule.Enable()
	stdCoreModules.Enable()
	stdAuthModules.Enable()

	verboseMode := *verbose || *vFlag

	response := engine.RunWorkflow(&boot.Options{
		Version:       Version,
		BuildTime:     BuildTime,
		EngineName:    "auth-cli",
		ConfigName:    "engine",
		Verbose:       verboseMode,
		Quiet:         false,
		Amount:        1,
		Retry:         1,
		RetryDelay:    0,
		RestartPolicy: "on-failure",
		Workflow:      workflow,
		LogPath:       "stdout",
		Config:        &domain.Config{},
		Args:          flag.Args(),
		Context:       nil,
		Settings:      nil,
	})

	for _, res := range response {
		if res.Error != nil {
			fmt.Printf("Error: %s\n", res.Error)
			os.Exit(1)
		}
		if res.Response != nil {
			fmt.Printf("Result: %v\n", res.Response)
		}
	}

	engine.ShutdownEngine()
}
