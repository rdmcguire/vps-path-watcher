package main

import (
	"net"
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
	vpsFirewall struct {
		Interval   string // Golang time duration e.g. 5s, 500ms, 1m30s
		Interfaces []vpsInterface
		LBTable    struct {
			Family string // ip ip6 inet etc...
			Name   string // Name of table
		}
		LBChain string
	}

	// Configuration for each downstream interface,
	// most likely wireguard interfaces
	vpsInterface struct {
		Name    string // Actual interface name
		Address string // Interface address with subnet
		Ratio   int8   // Scale of 1-10 (5 gets 50% of traffic)
		Target  string // Name of chain to send packets
		Checks  []*vpsHealthCheck
		nif     *net.Interface
		status  interfaceStatus
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
		Method       string  // HTTP: Method for check (e.g. GET)
		Request      string  // HTTP: Request (e.g. /healthz)
		Response     string  // HTTP: Expected Response (e.g. OK)
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
	}
)

// Perform all configured interface health checks
func (i *vpsInterface) healthChecks() {
	if i.status.healthChecks == nil {
		i.status.healthChecks = make(map[string]bool, len(i.Checks))
	}
	for _, c := range i.Checks {
		log.Tracef("Running health check %+v", c)
		log.WithFields(logrus.Fields{
			"nif":   i.Name,
			"check": c.Name,
			"type":  c.Type,
		}).Debug("Running Check")
		i.healthCheck(c)
	}
}

// Execute and record a health check
func (i *vpsInterface) healthCheck(c *vpsHealthCheck) {

	switch c.Type {
	case "tcp":
		i.status.healthChecks[c.Name] = c.checkTCP()
	case "icmp":
		i.status.healthChecks[c.Name] = c.checkICMP()
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
		"success": i.status.healthChecks[c.Name],
	}).Debug("Check Complete")
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
		log.Errorf("Pinger Failed for Check %s: %+v", c.Name, err)
		return false
	}

	// Check Results
	// MaxRTT and Packet Loss Toleration Optional
	stats := p.Statistics()
	log.Tracef("ICMP Stats for %s: %+v", c.Name, stats)

	// Check Average RTT
	if c.MaxRTT != 0 && stats.AvgRtt > time.Duration(c.MaxRTT*int(time.Millisecond)) {
		log.Warnf("ICMP Avg RTT Too High: %d", stats.AvgRtt)
		return false
	}

	// Check Packet Loss
	if c.MaxLossPcnt != 0 {
		if stats.PacketLoss > c.MaxLossPcnt {
			log.Warnf("ICMP Packet Loss Too High: %f", stats.PacketLoss)
			return false
		}
	} else if stats.PacketLoss == 100 {
		log.Warnf("Total ICMP Packet Loss for %s", c.Name)
		return false
	}

	// We made it, check is good
	return true
}

// Perform a TCP health check, supports a timeout
// as well as retries
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

func (s *interfaceStatus) healthy() bool {
	if !s.exists {
		return false
	} else if !s.up {
		return false
	} else if !s.addressed {
		return false
	}
	for _, v := range s.healthChecks {
		if !v {
			return false
		}
	}
	return true
}
