package topology

import "net/netip"

var unsafePublicIPv4Prefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("224.0.0.0/4"),
}

func usablePublicIPv4(address netip.Addr) bool {
	address = address.Unmap()
	if !address.IsValid() || !address.Is4() || !address.IsGlobalUnicast() ||
		address.IsPrivate() || address.IsLoopback() || address.IsLinkLocalUnicast() ||
		address.IsMulticast() || address.IsUnspecified() {
		return false
	}
	for _, prefix := range unsafePublicIPv4Prefixes {
		if prefix.Contains(address) {
			return false
		}
	}
	return true
}
