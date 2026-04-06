package modules

import (
	_ "github.com/kuetix/std-auth/modules/api/auth/transitions"

	di "github.com/kuetix/container"
	StdCoreModule "github.com/kuetix/std-core/modules"
)

func init() {
	di.Boot()
}

func Enable() {
	StdCoreModule.Enable()
}
