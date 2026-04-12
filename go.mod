module github.com/kuetix/std-auth

go 1.26.1

require (
	github.com/golang-jwt/jwt/v5 v5.3.1
	github.com/kuetix/container v0.1.0
	github.com/kuetix/engine v0.2.4
	github.com/kuetix/std-core v0.1.0
	github.com/kuetix/uuid v0.1.0
	golang.org/x/crypto v0.45.0
)

require (
	github.com/asaskevich/EventBus v0.0.0-20200907212545-49d423059eef // indirect
	github.com/fsnotify/fsnotify v1.9.0 // indirect
	github.com/go-viper/mapstructure/v2 v2.4.0 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/kuetix/helpers v1.0.0 // indirect
	github.com/kuetix/logger v1.0.0 // indirect
	github.com/mitchellh/mapstructure v1.5.0 // indirect
	github.com/pelletier/go-toml/v2 v2.2.4 // indirect
	github.com/sagikazarmark/locafero v0.12.0 // indirect
	github.com/spf13/afero v1.15.0 // indirect
	github.com/spf13/cast v1.10.0 // indirect
	github.com/spf13/pflag v1.0.10 // indirect
	github.com/spf13/viper v1.21.0 // indirect
	github.com/subosito/gotenv v1.6.0 // indirect
	go.yaml.in/yaml/v3 v3.0.4 // indirect
	golang.org/x/sys v0.42.0 // indirect
	golang.org/x/text v0.35.0 // indirect
	gopkg.in/ini.v1 v1.67.0 // indirect
)

replace http => .

replace github.com/kuetix/engine => ../../engine

replace github.com/kuetix/std-core => ../../packages/core
