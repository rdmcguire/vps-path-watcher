package main

import (
	"fmt"
	"io/ioutil"
	"time"

	"github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"
)

const (
	defInterval       = "1m"    // Default time between checks
	defTimeout        = "1s"    // Default timeout for health checks
	defRetryInterval  = "250ms" // Default wait between retries
	defICMPInterval   = "1s"    // Default ICMP Request Interval
	defWGMaxHandshake = "2m30s" // Max time since last Wireguard Peer handshake
	defMinTimeOut     = "30s"   // Minimum amount of time between checks of unhealthy interface (penalty box)
)

var (
	configFile string = "config.yaml"
	config     *vpsInstance
	logLevel   string = "info"
	log        *logrus.Logger
	interval   time.Duration
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
	config = new(vpsInstance)
	err = yaml.Unmarshal(yamlConf, config)
	if err != nil {
		log.Fatalf("Failed to unmashal yaml config: %+v", err)
	}

	// Set Interval
	interval = getDuration("config.Interval", config.Interval, defInterval)

	// Set minimum time unhealthy interface is pulled from chain
	config.minTimeOut = getDuration("Minimum Time Out", config.MinTimeOut, defMinTimeOut)

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
		// Max time since last wireguard peer handshake
		if i.Wireguard && i.WGPeer != "" {
			i.wgMaxHandshake = getDuration("Wireguard Max Handshake "+i.Name, i.WGMaxHandshake, defWGMaxHandshake)
		}

		for _, c := range i.Checks {
			// Timeout
			c.tmout = getDuration(fmt.Sprintf("Check timeout %s %s", i.Name, c.Name), c.Timeout, defTimeout)

			// Interval
			var checkDefaultInterval string
			if c.Type == "icmp" {
				checkDefaultInterval = defICMPInterval
			} else {
				checkDefaultInterval = defRetryInterval
			}
			c.reqInterval = getDuration(fmt.Sprintf("Check timeout %s %s", i.Name, c.Name), c.Interval, checkDefaultInterval)
		}
	}
}

// Given a wanted duration string and a fallback default,
// return a time.Duration
func getDuration(name string, d string, dd string) time.Duration {
	var duration time.Duration
	var err error

	// Use default if setting is empty
	if d == "" {
		d = dd
	}

	// Try wanted duration string
	duration, err = time.ParseDuration(d)
	if err != nil {
		// Return default otherwise -- trust the default
		duration, _ = time.ParseDuration(dd)
		log.Errorf("Failed to parse duration %s for %s: %v", d, name, err)
	}

	return duration
}
