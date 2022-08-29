package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"time"

	"github.com/go-ping/ping"
	"github.com/sirupsen/logrus"
)

const (
	defICMPPings = 3
)

type (
	// Configuration for VPS Path Watcher
	// LBTable and LBChain determine where
	// load balancer rules are placed
	vpsInstance struct {
		Interval   string // Golang time duration e.g. 5s, 500ms, 1m30s
		Interfaces []*vpsInterface
		MinTimeOut string `yaml:"minimumTimeOut"` // Minimum amount of time unhealthy interface is pulled
		LBTable    struct {
			Family string // ip ip6 inet etc...
			Name   string // Name of table
		}
		LBChain    string
		minTimeOut time.Duration
	}

	// Configuration for each downstream interface,
	// most likely wireguard interfaces
	vpsInterface struct {
		Name           string // Actual interface name
		Address        string // Interface address with subnet
		Wireguard      bool   // Set to true if wireguard interface
		WGPeer         string // Peer ID to check for liveness
		WGMaxHandshake string `yaml:"wgLastHandshake"` // Max time since last peer handshake, go time (e.g. 1m30s)
		Ratio          int8   // Scale of 1-10 (5 gets 50% of traffic)
		Target         string // Name of chain to send packets
		Mark           uint8  // Mark to add to packets. Does not create rule if left at 0x0
		Counter        bool   // Use counter if Mark defined (managed rule)
		Checks         []*vpsHealthCheck
		nif            *net.Interface
		status         *interfaceStatus
		lastStatus     *interfaceStatus
		lastUnhealthy  time.Time
		wgMaxHandshake time.Duration
	}

	// Configure the health check
	vpsHealthCheck struct {
		Name         string  // Name of health check
		Type         string  // ICMP, TCP, UDP
		Host         string  // Host to perform check against
		Port         string  // 22, 443, etc..
		Interval     string  // Golang time duration, interval between retries / pings
		Timeout      string  // Golang time duration (e.g. 750ms, 2s, 1m12s). For ICMP, total time of all messages.
		Retries      int     // Number of retries for check
		Count        int     // ICMP: Number of pings to send
		MaxRTT       int     // ICMP: Max AVERAGE Round-Trip Time
		MaxLossPcnt  float64 // ICMP: Max percentage of packets lost
		TLS          bool    // HTTP: Use TLS [HTTPS]
		Insecure     bool    // HTTP: Valid Handshake
		Method       string  // HTTP: Method for check (e.g. GET)
		Path         string  // HTTP: Request path (e.g. /healthz)
		MatchRegEx   string  `yaml:"matchRegEx"`   // HTTP: Expected Response RegEx
		ResponseCode int     `yaml:"responseCode"` // HTTP: Expected Response Code (e.g. 200)
		tmout        time.Duration
		reqInterval  time.Duration
	}

	// Checks performed on interface
	interfaceStatus struct {
		exists       bool
		up           bool
		addressed    bool
		healthChecks map[string]bool
		time         time.Time
	}
)

// Perform all configured interface health checks
func (i *vpsInterface) healthChecks() {
	if i.status.healthChecks == nil {
		i.status.reset(len(i.Checks))
	}

	// Perform provisionend checks
	for _, c := range i.Checks {
		log.Tracef("Running health check %+v", c)
		log.WithFields(logrus.Fields{
			"nif":   i.Name,
			"check": c.Name,
			"type":  c.Type,
			"host":  c.Host,
		}).Debug("Running Check")
		i.healthCheck(c)
	}

	// Perform WG Checks if configured
	if i.Wireguard {
		checkWgHealth(i)
	}
}

// Execute and record a health check
func (i *vpsInterface) healthCheck(c *vpsHealthCheck) {

	switch c.Type {
	case "tcp":
		i.status.healthChecks[c.Name] = c.checkTCP()
	case "icmp":
		i.status.healthChecks[c.Name] = c.checkICMP()
	case "http":
		i.status.healthChecks[c.Name] = c.checkHTTP()
	default:
		log.WithFields(logrus.Fields{
			"nif":   i.Name,
			"check": c.Name,
			"type":  c.Type,
		}).Warn("Skipping Unknown Health Check")
		return
	}
	log.WithFields(logrus.Fields{
		"nif":     i.Name,
		"check":   c.Name,
		"type":    c.Type,
		"host":    c.Host,
		"success": i.status.healthChecks[c.Name],
	}).Debug("Check Complete")
}

// Performans an HTTP health check
// Supports interval, retries, method, path, response regex,
// and expected response code
//
// Options for https and tlsVerify
func (c *vpsHealthCheck) checkHTTP() bool {
	// Prepare HTTP Client
	tlsConfig := &tls.Config{
		InsecureSkipVerify: c.Insecure,
	}
	transport := &http.Transport{
		TLSClientConfig:     tlsConfig,
		TLSHandshakeTimeout: c.tmout,
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   c.tmout,
	}

	// Prepare RegEx
	var re *regexp.Regexp
	var err error
	if c.MatchRegEx != "" {
		re, err = regexp.Compile(c.MatchRegEx)
		if err != nil {
			log.Warnf("Check %s bad regex %s: %+v", c.Name, c.MatchRegEx, err)
			return false
		}
	}

	// Prepare URI
	var proto string
	if c.TLS {
		proto = "https"
	} else {
		proto = "http"
	}
	uri := proto + "://" + c.Host + c.Path

	fields := map[string]any{
		"check":  c.Name,
		"method": c.Method,
		"path":   c.Path,
		"uri":    uri,
	}

	// Make request and perform checks
	switch c.Method {
	case "GET":
		for i := -1; i < c.Retries; i++ {
			resp, err := client.Get(uri)
			if err != nil {
				log.WithFields(fields).WithField("error", err).
					Warn("Check Failed HTTP Connect")
				time.Sleep(c.reqInterval)
				continue
			}
			// Check response code
			if c.ResponseCode != resp.StatusCode {
				log.WithFields(fields).WithFields(logrus.Fields{
					"responseWanted":   c.ResponseCode,
					"responseRecieved": resp.StatusCode,
				}).Warn("Check Failed HTTP Response Code")
				return false
			}
			// Check body against regex
			if c.MatchRegEx != "" {
				defer resp.Body.Close()
				body, _ := io.ReadAll(resp.Body)
				if !re.Match(body) {
					log.WithFields(fields).WithField("wantedRegEx", c.MatchRegEx).
						Warn("Check Failed HTTP Body Match")
					log.Tracef("Response Body: %s", body)
					return false
				}
			}
			return true
		}
	default:
		log.Warnf("Unimplemented method %s, check failed", c.Method)
		return false
	}
	return false
}

// Performans an ICMP health check
// Supports interval, timeout, count, maxrtt and maxlosspcnt
//
// If maxrtt or maxlosspcnt are specified, high rtt or icmp failures
// can result in a failure. Otherwise only 100% failure.
func (c *vpsHealthCheck) checkICMP() bool {
	// Set Defaults
	if c.Count == 0 {
		c.Count = defICMPPings
	}
	fields := map[string]any{
		"check":    c.Name,
		"host":     c.Host,
		"count":    c.Count,
		"interval": c.reqInterval,
		"timeout":  c.Timeout,
	}

	// Prepare Pinger
	p, err := ping.NewPinger(c.Host)
	if err != nil {
		log.Errorf("Failed to Prepare Pinger: %+v", err)
		return false
	}
	p.Count = c.Count
	p.Interval = c.reqInterval
	p.Timeout = c.tmout
	log.Tracef("Pinger Configured: %+v", p)

	// Run
	err = p.Run()
	if err != nil {
		log.WithFields(fields).WithField("error", err).Error("ICMP Check Failed")
		return false
	}

	// Check Results
	// MaxRTT and Packet Loss Toleration Optional
	stats := p.Statistics()
	log.Tracef("ICMP Stats for %s: %+v", c.Name, stats)

	// Check Average RTT
	if c.MaxRTT != 0 && stats.AvgRtt > time.Duration(c.MaxRTT*int(time.Millisecond)) {
		log.WithFields(fields).WithField("avgRTT", stats.AvgRtt).
			WithField("wantedRTT", c.MaxRTT).Warn("Check Failed ICMP RTT")
		return false
	}

	// Check Packet Loss
	if c.MaxLossPcnt != 0 {
		if stats.PacketLoss > c.MaxLossPcnt {
			log.WithFields(fields).WithField("MaxLossPercent", c.MaxLossPcnt).
				WithField("ObservedLossPcnt", stats.PacketLoss).
				Warn("Check Failed ICMP Packet Loss")
			return false
		}
	} else if stats.PacketLoss == 100 {
		log.WithFields(fields).Warn("Check Failed ICMP Packet Loss")
		return false
	}

	// We made it, check is good
	return true
}

// Perform a TCP health check, supports a timeout
// as well as retries and interval between checks
//
// Does not send or receive any data
func (c *vpsHealthCheck) checkTCP() bool {
	// Attempt TCP Connect
	target := net.JoinHostPort(c.Host, c.Port)
	for i := -1; i < c.Retries; i++ {
		conn, err := net.DialTimeout("tcp", target, c.tmout)
		// Failed
		if err != nil {
			log.Warnf("Check %s failed attempt %d", c.Name, i+2)
			time.Sleep(c.reqInterval)
			continue
		}
		// Succeeded
		if conn != nil {
			conn.Close()
			return true
		}
	}
	return false
}

// Basic health checks for defined interface
// Checks to ensure the interface exists, is up,
// and has the expected address
func (i *vpsInterface) basicChecks() {
	// Make sure the interface is present
	var exists bool
	exists, i.nif = getInterface(i.Name)

	// Perform checks if interface exists
	if exists {
		log.Tracef("Found Interface: %+v", i.nif)
		i.status.exists = true

		// Make sure it's up
		if i.checkInterfaceUp() {
			log.Debugf("Interface %s is UP", i.Name)
			i.status.up = true
		}

		// Make sure it's configured as expected
		if i.checkIPv4Address() {
			log.Debugf("Interface %s has address %s", i.Name, i.Address)
			i.status.addressed = true
		}
	}
}

// Checks to see if an interface has the IP Address
// assigned, and matching what is expected
func (i *vpsInterface) checkIPv4Address() bool {
	addrs, err := i.nif.Addrs()
	if err != nil {
		log.Errorf("Failed to get interface %s addresses: %+v", i.Name, err)
		return false
	}
	for _, a := range addrs {
		log.WithFields(logrus.Fields{
			"nif":  i.Name,
			"addr": a,
		}).Trace("Found IP Address")
		if a.String() == i.Address {
			return true
		}
	}
	return false
}

// Checks to see if provided interface is up
func (i *vpsInterface) checkInterfaceUp() bool {
	log.Tracef("Interface %s status: %v", i.Name, i.nif.Flags&net.FlagUp)
	if i.nif.Flags&net.FlagUp != 0 {
		return true
	}
	log.Warnf("Interface %s is not up!", i.Name)
	return false
}

// Checks if interface exists, returns it if so
func getInterface(name string) (bool, *net.Interface) {
	nif, err := net.InterfaceByName(name)
	if err != nil {
		log.Errorf("No interface %s: %v", name, err)
		return false, nil
	}
	return true, nif
}

// Resets stats for all interfaces
func resetHealth() {
	for _, i := range config.Interfaces {
		i.status = new(interfaceStatus)
	}
}

// Resets health status for given interface
func (s *interfaceStatus) reset(numChecks int) {
	s.healthChecks = make(map[string]bool, numChecks)
}

// Checks all interfaces for health
func (s *interfaceStatus) healthy() (bool, []string) {
	healthy := true
	var reasons []string
	if !s.exists {
		healthy = false
		reasons = append(reasons, "Interface does not exist")
	} else if !s.up {
		healthy = false
		reasons = append(reasons, "Interface is no up")
	} else if !s.addressed {
		healthy = false
		reasons = append(reasons, "Interface not properly addressed")
	}
	for c, v := range s.healthChecks {
		if !v {
			healthy = false
			reasons = append(reasons, fmt.Sprintf("Failed %s", c))
		}
	}
	return healthy, reasons
}
