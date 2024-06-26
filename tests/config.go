package tests

import (
	"log"

	"github.com/oasisprotocol/oasis-web3-gateway/conf"
)

var TestsConfig *conf.Config

// InitTestsConfig initializes configuration file for tests.
func InitTestsConfig() (err error) {
	//TestsConfig, err = conf.InitConfig("../../conf/tests.yml")
	TestsConfig, err = conf.InitConfig("../../conf/w3-gateway-03.yml")

	return
}

// MustInitConfig initializes configuration for tests or exits.
func MustInitConfig() {
	err := InitTestsConfig()
	if err != nil {
		log.Fatalf("failed to init config: %v", err)
	}
}
