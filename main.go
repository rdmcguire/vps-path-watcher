package main

import (
	"flag"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/sirupsen/logrus"
)

var (
	wg sync.WaitGroup
)

func init() {
	flag.StringVar(&configFile, "config", configFile, "Path to config yaml")
	flag.StringVar(&logLevel, "logLevel", logLevel, "Default logging level")
	flag.Parse()

	// Load config from file
	loadConfig()
	log.Debugf("Yaml Config: %+v", config)
}

func main() {
	log.Info("VPS Path Watcher Ready")

	// Handle signals
	die := make(chan os.Signal)
	hup := make(chan os.Signal)
	signal.Notify(die, syscall.SIGINT, syscall.SIGTERM)
	signal.Notify(hup, syscall.SIGHUP)

	// Run every config.interval seconds
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// Don't wait for first tick to run
	checkInterfaces()

	// Update forever
	for {
		select {
		case <-hup:
			log.Warn("Received SIGHUP, waiting on goroutines then reloading config.")
			wg.Wait()
			loadConfig()
		case <-die:
			log.Warn("Asked to die, waiting on goroutines...")
			wg.Wait()
			os.Exit(0)
		case <-ticker.C:
			checkInterfaces()
		}
	}
}

func checkInterfaces() {
	wg.Add(1)
	for _, i := range config.Interfaces {
		log.WithFields(logrus.Fields{
			"nif":    i.Name,
			"addr":   i.Address,
			"checks": len(i.Checks),
		}).Info("Running Interface Checks")

		// Check Health
		i.basicChecks()
		i.healthChecks()

		// Check Results
		log.Tracef("Check Results for %s: %+v", i.Name, i.status)
		log.Infof("Interface %s healthy: %t", i.Name, i.status.healthy())
	}
	wg.Done()
}
