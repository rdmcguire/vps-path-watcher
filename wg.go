package main

import (
	"time"

	"github.com/sirupsen/logrus"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

var (
	client  *wgctrl.Client
	devices []*wgtypes.Device
)

func wgInit() {
	// Create Client
	var err error
	client, err = wgctrl.New()
	if err != nil {
		log.Fatalf("Unable to create wireguard client: %+v", err)
	}

	// Debug Devices
	getWgDevs()
	printWgDevs(devices)

	// Check if our declared wg devices exist
	for _, i := range config.Interfaces {
		if i.Wireguard {
			d := getWgDev(i.Name)
			if d == nil {
				log.Errorf("Declared wireguard device %s not found", i.Name)
			}
		}
	}
}

// Health Checks for Wireguard Interface
// Updates i.status.healthChecks[]
func checkWgHealth(i *vpsInterface) {
	// Refresh Devices
	getWgDevs()
	// Retrieve the device
	device := getWgDev(i.Name)
	if device == nil {
		i.status.healthChecks["wg_dev_exists"] = false
		return
	} else {
		i.status.healthChecks["wg_dev_exists"] = true
	}

	// Check for peer
	if i.WGPeer != "" {
		peer := getWgPeer(device, i.WGPeer)
		if peer == nil {
			log.Warnf("Check Failed Wireguard Peer %s %s", i.Name, i.WGPeer)
			i.status.healthChecks["wg_has_peer"] = false
		} else {
			log.Debugf("Found peer %s for interface %s", peer.PublicKey.PublicKey(), i.Name)
			i.status.healthChecks["wg_has_peer"] = true
			// Now check last peer handshake
			i.checkWgLastHandshake(peer)
		}
	}
}

// Checks the last peer handshake and compares to
// vpsInterface.WGMaxHandshake
func (i *vpsInterface) checkWgLastHandshake(peer *wgtypes.Peer) {
	timeSince := time.Since(peer.LastHandshakeTime)
	if timeSince > i.wgMaxHandshake {
		log.WithFields(logrus.Fields{
			"nif":            i.Name,
			"peer":           peer.PublicKey.String(),
			"lastHandshake":  peer.LastHandshakeTime,
			"timeSince":      timeSince,
			"maxTimeAllowed": i.wgMaxHandshake,
		}).Warn("Check Failed Wireguard Peer Last Handshake")
		i.status.healthChecks["wg_last_handshake"] = false
	} else {
		log.Debugf("Wireguard peer %s last handshake OK: %s",
			peer.PublicKey.String(), timeSince)
		i.status.healthChecks["wg_last_handshake"] = true
	}
}

// Retrieves a wireguard peer by name
func getWgPeer(device *wgtypes.Device, peerID string) *wgtypes.Peer {
	var peer *wgtypes.Peer
	for _, p := range device.Peers {
		if p.PublicKey.String() == peerID {
			log.Debugf("Wireguard device %s peer %s found", device.Name, p.PublicKey.String())
			peer = &p
			break
		}
	}
	return peer
}

// Retrieves a wireguard device by name
func getWgDev(name string) *wgtypes.Device {
	var device *wgtypes.Device
	for _, d := range devices {
		if d.Name == name {
			log.Debugf("Wireguard device %s found", name)
			device = d
			break
		}
	}
	return device
}

// Fetches / refreshes wireguard devices
func getWgDevs() {
	var err error
	devices, err = client.Devices()
	if err != nil {
		log.Fatalf("Failed to retrieve wireguard devices: %+v", err)
	}
}

// Trace prints wireguard devices
// This is necessary because the private key
// will by default be printed!
func printWgDevs(devs []*wgtypes.Device) {
	for _, d := range devs {
		log.Tracef("Wireguard Device %s:\n\tType: %s\n\tPubKey: %s\n\tPort: %d\n\tMark: %x\n\tPeers: %+v",
			d.Name, d.Type.String(), d.PublicKey.String(), d.ListenPort, d.FirewallMark, d.Peers)
	}
}
