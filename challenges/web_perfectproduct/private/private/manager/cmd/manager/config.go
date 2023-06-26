package main

import (
	"log"
	"os"
	"time"

	"github.com/kelseyhightower/envconfig"
)

var Config *config

func init() {
	var s config
	err := envconfig.Process("", &s)
	if err != nil {
		log.Fatal(err.Error())
	}
	Config = &s

	err = os.WriteFile("/tmp/create_sandbox.sh", []byte(CreateSandboxSh), 0700)
	if err != nil {
		log.Fatal(err.Error())
	}
	err = os.WriteFile("/tmp/destroy_sandbox.sh", []byte(DestroySandboxSh), 0700)
	if err != nil {
		log.Fatal(err.Error())
	}
	err = os.WriteFile("/tmp/clean_all_sandbox.sh", []byte(CleanAllSandboxSh), 0700)
	if err != nil {
		log.Fatal(err.Error())
	}
}

const CreateSandboxSh = `#!/bin/bash

set -ex
name="$1"
port="$2"

docker run -d --rm --name="web-perfect-product-$name" -p "$port:80" web-perfect-product
`

const DestroySandboxSh = `#!/bin/bash

set -ex
name="$1"

docker kill "web-perfect-product-$name"
`

const CleanAllSandboxSh = `#!/bin/bash

set -ex

# kill running containers
DOCKERS_CONTAINERS=$(docker ps -a --format "{{.Names}}" | grep "web-perfect-product-") || true
if [ -z "$DOCKERS_CONTAINERS" ]; then
  echo "no containers to kill"
else
  echo "killing"
  docker kill $DOCKERS_CONTAINERS
fi;
`

type config struct {
	Listen string `default:"0.0.0.0:80" split_words:"true"`

	HttpPassword string `default: ""`

	SandboxDuration       time.Duration `default:"600s" split_words:"true"`
	SandboxNewCreation    time.Duration `default:"600s" split_words:"true"`
	SandboxRequestTimeout time.Duration `default:"100s" split_words:"true"`

	OneTimeHashDuration time.Duration `default:"60s" split_words:"true"`

	HashcashDifficult int `default:"26" split_words:"true"`
	MaxCores          int `default:"16" split_words:"true"`
}
