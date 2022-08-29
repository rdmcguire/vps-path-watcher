package main

import (
	"io/ioutil"
	"time"

	"github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"
)

const (
	defInterval      = "1m"
	defTimeout       = "1s"
	defRetryInterval = "250ms"
	defICMPInterval  = "1s"
)

var (
	configFile      string = "config.yaml"
	config          *vpsFirewall
	logLevel        string = "info"
	log             *logrus.Logger
	wgLastHandshake string = "5m"
	interval        time.Duration
)

func loadConfig() {

	// Logging
	level, err := logrus.ParseLevel(logLevel)
	if err != nil {
		level = logrus.InfoLevel
	}
	log = logrus.New()
	log.SetLevel(level)

	// Config
	log.Debugf("Reading configuration from %s", configFile)
	yamlConf, err := ioutil.ReadFile(configFile)
	if err != nil {
		log.Fatalf("Failed to read config file %s: %+v", configFile, err)
	}

	// Unmarshal yaml
	config = new(vpsFirewall)
	err = yaml.Unmarshal(yamlConf, config)
	if err != nil {
		log.Fatalf("Failed to unmashal yaml config: %+v", err)
	}

	// Set Interval
	if config.Interval == "" {
		config.Interval = defInterval
	}
	interval, err = time.ParseDuration(config.Interval)
	if err != nil {
		log.Fatalf("Failed to parse execution interval %s: %+v", config.Interval, err)
	}

	// Prepare wireguard client if any wg interfaces
	// are configured.
	//
	// Will force a check for last handshake if WGPeer given,
	// max last handshake configurable via flag
	for _, i := range config.Interfaces {
		if i.Wireguard {
			wgInit()
			break
		}
	}

	// Handle Durations
	for _, i := range config.Interfaces {
		for _, c := range i.Checks {
			// Timeout
			if c.Timeout == "" {
				c.Timeout = defTimeout
			}
			c.tmout, err = time.ParseDuration(c.Timeout)
			if err != nil {
				log.WithFields(logrus.Fields{
					"nif":     i.Name,
					"check":   c.Name,
					"timeout": c.Timeout,
					"error":   err,
				}).Error("Failed to parse check timeout, using default")
				c.tmout, _ = time.ParseDuration(defTimeout)
			}

			// Interval
			if c.Interval == "" {
				if c.Type == "icmp" {
					c.Interval = defICMPInterval
				} else {
					c.Interval = defRetryInterval
				}
			}
			c.reqInterval, err = time.ParseDuration(c.Interval)
			if err != nil {
				log.WithFields(logrus.Fields{
					"nif":      i.Name,
					"check":    c.Name,
					"interval": c.Interval,
					"error":    err,
				}).Error("Failed to parse check timeout, using default")
				if c.Type == "icmp" {
					c.reqInterval, _ = time.ParseDuration(defRetryInterval)
				} else {
					c.reqInterval, _ = time.ParseDuration(defICMPInterval)
				}
			}
		}
	}
}
