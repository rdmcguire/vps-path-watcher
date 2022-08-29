package main

import (
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
	devices, err = client.Devices()
	if err != nil {
		log.Fatalf("Failed to retrieve wireguard devices: %+v", err)
	}
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
			log.Warnf("Wireguard interface %s missing peer %s", i.Name, i.WGPeer)
			i.status.healthChecks["wg_has_peer"] = false
		} else {
			i.status.healthChecks["wg_has_peer"] = true
		}
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

// Trace prints wireguard devices
// This is necessary because the private key
// will by default be printed!
func printWgDevs(devs []*wgtypes.Device) {
	for _, d := range devs {
		log.Tracef("Wireguard Device %s:\n\tType: %s\n\tPubKey: %s\n\tPort: %d\n\tMark: %x\n\tPeers: %+v",
			d.Name, d.Type.String(), d.PublicKey.String(), d.ListenPort, d.FirewallMark, d.Peers)
	}
}
