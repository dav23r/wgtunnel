package main

import (
	"fmt"
	"os"
	"os/signal"
	"sync"
	"os/exec"
	"net"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"github.com/vishvananda/netlink"
)

const wgIfName = "wg-tunnel"
const listenPort = 51820
const wgAddrServer = "10.0.0.1/24"
const wgAddrClient = "10.0.0.2/24"

const nginxPublishedPort = "8080"
const nginxBindAddr = "10.0.0.1"

const peerAddrServer = "10.0.0.1/32"
const peerAddrClient = "10.0.0.2/32"


func main() {
	fmt.Println ("<Wireguard Tunnel>")
	if len(os.Args) == 1 {
		/* Deploy a server endpoint */
		fmt.Println ("Deploying server side of the tunnel")
		serverEndpoint()
	} else {
		/* Deploy a client endpoint */
		fmt.Println ("Deploying client side of the tunnel")
		serverPublicKey, err := wgtypes.ParseKey(os.Args[1])
		if err != nil {
			fmt.Println ("Invalid arguments, exiting")
			os.Exit(1)
		}
		clientPrivateKey, err := wgtypes.ParseKey(os.Args[2])
		if err != nil {
			fmt.Println ("Invalid arguments, exiting")
			os.Exit(1)
		}
		serverPublicIP := os.Args[3]
		clientEndpoint(serverPublicKey, clientPrivateKey, serverPublicIP)
	}
}

func serverEndpoint() {
	configureWgInterfaceNetlink(wgAddrServer)
	configureWgInterfaceProtocolServer()
	runDockerNginx()
}

func clientEndpoint(serverPublicKey wgtypes.Key, clientPrivateKey wgtypes.Key, serverPublicIP string) {
	configureWgInterfaceNetlink(wgAddrClient)
	configureWgInterfaceProtocolClient(serverPublicKey, clientPrivateKey, serverPublicIP)
	runDockerCurl()
}

func configureWgInterfaceNetlink(wgAddr string) {
	wgIf, err := netlink.LinkByName(wgIfName)
	if err == nil {
		/* Remove existing interface */
		fmt.Printf ("Interface exists: %s, deleting to recreate\n", wgIfName)
		netlink.LinkDel(wgIf)
	}
	addIf := exec.Command("ip", "link", "add", wgIfName, "type", "wireguard")
	if err := addIf.Run(); err != nil {
		fmt.Printf ("Error adding wireguard interface [ip link add ...]: %v\n", err)
		os.Exit(1)
	} else {
		fmt.Println ("Interface added")
	}
	wgIf, _ = netlink.LinkByName(wgIfName)
	addr, _ := netlink.ParseAddr(wgAddr)
	netlink.AddrAdd(wgIf, addr)
	netlink.LinkSetUp(wgIf)
}

func configureWgInterfaceProtocolClient(serverPublicKey wgtypes.Key, clientPrivateKey wgtypes.Key, serverPublicIP string) {
	c, err := wgctrl.New()
	if err != nil {
		fmt.Printf ("Error creating wgctrl instance: %v\n", err)
		os.Exit(1)
	}

	_, ipnet, err := net.ParseCIDR(peerAddrServer)
	if err != nil {
		fmt.Println ("Can't parse server endpoint's tunnel ip address")
		os.Exit(1)
	}
	serverPubUDP, err := net.ResolveUDPAddr("", serverPublicIP + ":" +  fmt.Sprintf("%d", listenPort))
	if err != nil {
		fmt.Printf ("Can't parse server endpoint's public ip address: %v\n", err)
		os.Exit(1)
	}
	peerConfig := wgtypes.PeerConfig {
		PublicKey : wgtypes.Key(serverPublicKey),
		ReplaceAllowedIPs : true,
		AllowedIPs : []net.IPNet{ *ipnet },
		Endpoint : serverPubUDP,
	}

	clientConfig := wgtypes.Config {
		PrivateKey : &clientPrivateKey,
		ReplacePeers : true,
		Peers : []wgtypes.PeerConfig{peerConfig},
	}

	if err := c.ConfigureDevice(wgIfName, clientConfig); err != nil {
		fmt.Printf ("Error applying client configuariont: %v\n", err)
		os.Exit(1)
	} else {
		fmt.Println ("Successfully applied client endpoint configuration")
	}
}

func configureWgInterfaceProtocolServer() {
	c, err := wgctrl.New()
	if err != nil {
		fmt.Printf ("Error creating wgctrl instance: %v\n", err)
		os.Exit(1)
	}

	peerPrivateKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		fmt.Printf ("Error generating key pair for peer: %v\n", err)
		os.Exit(1)
	}
	peerPublicKey := peerPrivateKey.PublicKey()

	_, ipnet, err := net.ParseCIDR(peerAddrClient)
	if err != nil {
		fmt.Printf ("Can't parse client's tunnel ip address: %v\n", err)
		os.Exit(1)
	}
	peerConfig := wgtypes.PeerConfig {
		PublicKey : peerPublicKey,
		ReplaceAllowedIPs : true,
		AllowedIPs : []net.IPNet{ *ipnet },
	}

	serverPrivateKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		fmt.Printf ("Error generating server key pair: %v\n", err)
		os.Exit(1)
	}
	serverPublicKey := serverPrivateKey.PublicKey()

	listenPortCopy := listenPort
	serverConfig := wgtypes.Config {
		PrivateKey : &serverPrivateKey,
		ListenPort : &listenPortCopy,
		ReplacePeers : true,
		Peers : []wgtypes.PeerConfig{peerConfig},
	}

	if err := c.ConfigureDevice(wgIfName, serverConfig); err != nil {
		fmt.Printf ("Error applying server configuariont: %v\n", err)
		os.Exit(1)
	} else {
		fmt.Println ("Successfully applied server endpoint configuration")
	}

	fmt.Println("On client, run specifying ip of server where deployment was made:")
	fmt.Printf("\t$ ./tunnel %s %s <public ip of server>\n", serverPublicKey.String(), peerPrivateKey.String())
	c.Close()
}

func runDockerNginx() {
	nginxCommand := exec.Command("docker", "run", "--rm", "-d", "-p",
		fmt.Sprintf("%s:80", nginxPublishedPort), "--name", "nginx", "nginx")
	fmt.Println ("Starting Nginx container")
	if out, err := nginxCommand.CombinedOutput(); err != nil {
		fmt.Println (string(out))
		os.Exit(1)
	} else {
		fmt.Printf ("Nginx started on %s:%s, to test run on the client:\n", nginxBindAddr, nginxPublishedPort)
		fmt.Println ("\t$ curl" + " " + nginxBindAddr + ":" + nginxPublishedPort)
		fmt.Println ("Issue ^-C to tear down the setup")
		waitForInterrupt(stopDockerNginx)
	}
}

func stopDockerNginx() {
	nginxCommand := exec.Command("docker", "container", "stop", "nginx")
	if out, err := nginxCommand.CombinedOutput(); err != nil {
		fmt.Println (string(out))
		os.Exit(1)
	} else {
		fmt.Println ("Nginx stopped, exiting gracefully")
	}
}

func runDockerCurl() {
	clientCommand := exec.Command("docker", "run", "--rm", "-d", "-it", "--name", "curlContainer", "tutum/curl")
	fmt.Println ("Starting curl container")
	if out, err := clientCommand.CombinedOutput(); err != nil {
		fmt.Println (string(out))
		os.Exit(1)
	} else {
		fmt.Printf ("Client curl image started successfully, to test, run on other terminal:\n")
		fmt.Printf("\t$ docker exec -it curlContainer curl %s:%s\n", nginxBindAddr, nginxPublishedPort)
		fmt.Println ("Issue ^-C to tear down the setup")
		waitForInterrupt(stopDockerCurl)
	}
}

func stopDockerCurl() {
	nginxCommand := exec.Command("docker", "container", "stop", "curlContainer")
	if out, err := nginxCommand.CombinedOutput(); err != nil {
		fmt.Println (string(out))
		os.Exit(1)
	} else {
		fmt.Println ("Client ubuntu image stopped, exiting gracefully")
	}
}

func waitForInterrupt(f func ()) {
    var end_waiter sync.WaitGroup
    end_waiter.Add(1)
    var signal_channel chan os.Signal
    signal_channel = make(chan os.Signal, 1)
    signal.Notify(signal_channel, os.Interrupt)
    go func() {
        <-signal_channel
		f()
        end_waiter.Done()
    }()
    end_waiter.Wait()
}
