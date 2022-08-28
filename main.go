package main

import (
	"flag"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/sirupsen/logrus"
)

var (
	wg            sync.WaitGroup
	currentStatus string
)

func init() {
	flag.StringVar(&configFile, "config", configFile, "Path to config yaml")
	flag.StringVar(&logLevel, "logLevel", logLevel, "Default logging level")
	flag.Parse()

	// Load config from file
	loadConfig()
	log.Debugf("Yaml Config: %+v", config)

	// Prepare NFTables
	initNFT()
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
			initNFT()
		case <-die:
			log.Warn("Asked to die, waiting on goroutines...")
			wg.Wait()
			os.Exit(0)
		case <-ticker.C:
			go checkInterfaces()
		}
	}
}

// Main Loop
// Checks each interface for basic health (up,configured)
// Performs configured health checks
//
// Once all checks are complete, takes action on
// NFTables if necessary
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

		// Check Result
		log.Tracef("Check Results for %s: %+v", i.Name, i.status)
		healthy, reasons := i.status.healthy()
		if healthy {
			log.WithField("nif", i.Name).Info("Checks Complete, Interface Healthy")
		} else {
			log.WithFields(logrus.Fields{
				"nif":     i.Name,
				"reasons": reasons,
			}).Error("Checks Complete, Interface Unhealthy")
		}
	}

	// Determine Desired Status
	desiredStatus := currentStatus
	healthyInterfaces := getHealthyInterfaces()
	if healthyInterfaces == nil {
		log.Error("No healthy interfaces, refusing to do anything")
	} else if len(healthyInterfaces) < len(config.Interfaces) {
		log.Warn("Interfaces degraded, routing to healthy only")
		var ss []string
		for _, i := range healthyInterfaces {
			ss = append(ss, i.Name)
		}
		desiredStatus = strings.Join(ss, "|")
	} else {
		desiredStatus = "all"
	}

	// Take Action
	if currentStatus != desiredStatus {
		log.WithFields(logrus.Fields{
			"currentStatus": currentStatus,
			"desiredStatus": desiredStatus,
		}).Warn("Adjusting NFTables Load Balancing")
		currentStatus = updateNFT(desiredStatus)
	}

	wg.Done()
}

// Returns slice of all healthy interfaces
func getHealthyInterfaces() []*vpsInterface {
	var healthyInterfaces []*vpsInterface
	for _, i := range config.Interfaces {
		healthy, _ := i.status.healthy()
		if healthy {
			healthyInterfaces = append(healthyInterfaces, i)
		}
	}
	return healthyInterfaces
}
