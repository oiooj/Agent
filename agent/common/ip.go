package common

import (
	"net"
	"strconv"
	"strings"
)

func IP() (ips []string, err error) {
	ips = make([]string, 0)

	ifaces, e := net.Interfaces()
	if e != nil {
		return ips, e
	}

	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 {
			continue // interface down
		}

		if iface.Flags&net.FlagLoopback != 0 {
			continue // loopback interface
		}

		// ignore docker and warden bridge
		if !HasInterfacePrefix(iface.Name) {
			continue
		}

		addrs, e := iface.Addrs()
		if e != nil {
			return ips, e
		}

		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}

			// IP filter
			// 224.0.0
			// 169.254.0.0/16
			if ip == nil || ip.IsLoopback() || ip.IsLinkLocalMulticast() || ip.IsLinkLocalUnicast() {
				continue
			}

			ip = ip.To4()
			if ip == nil {
				continue // not an ipv4 address
			}

			ipStr := ip.String()
			// append all IP
			ips = append(ips, ipStr)
		}
	}

	return ips, nil
}

func HasInterfacePrefix(ifacename string) bool {
	for _, prefix := range Conf.IfacePrefix {
		if strings.HasPrefix(ifacename, prefix) {
			return true
		}
	}
	return false
}

func IsIntranet(ipStr string) bool {
	if strings.HasPrefix(ipStr, "10.") || strings.HasPrefix(ipStr, "192.168.") {
		return true
	}

	if strings.HasPrefix(ipStr, "172.") {
		// 172.16.0.0-172.31.255.255
		arr := strings.Split(ipStr, ".")
		if len(arr) != 4 {
			return false
		}

		second, err := strconv.ParseInt(arr[1], 10, 64)
		if err != nil {
			return false
		}

		if second >= 16 && second <= 31 {
			return true
		}
	}

	return false
}
