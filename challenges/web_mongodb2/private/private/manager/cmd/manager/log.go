package main

import "github.com/sirupsen/logrus"

var Log *logrus.Logger

func init() {
	Log = logrus.New()
}
