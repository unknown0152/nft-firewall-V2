package nft

// EmergencyDenyScript is deliberately independent of configuration and
// SQLite. Early boot installs it only when enforcement was previously enabled
// but the committed snapshot cannot be verified.
const EmergencyDenyScript = `table inet nftfw_filter {
    chain input {
        type filter hook input priority filter; policy drop;
        iifname "lo" accept comment "nftfw:emergency-loopback"
        counter drop comment "nftfw:input-default-deny"
    }
    chain output {
        type filter hook output priority filter; policy drop;
        oifname "lo" accept comment "nftfw:emergency-loopback"
        counter drop comment "nftfw:output-default-deny"
    }
    chain forward {
        type filter hook forward priority filter; policy drop;
        counter drop comment "nftfw:forward-default-deny"
    }
}
table ip nftfw_nat {
    chain prerouting {
        type nat hook prerouting priority dstnat; policy accept;
        counter comment "nftfw:dnat-chain"
    }
    chain postrouting {
        type nat hook postrouting priority srcnat; policy accept;
        counter comment "nftfw:vpn-only-nat"
    }
}
table ip6 nftfw_filter6 {
    chain input {
        type filter hook input priority -300; policy drop;
        iifname "lo" accept comment "nftfw:ipv6-mode-disabled"
    }
    chain output {
        type filter hook output priority -300; policy drop;
        oifname "lo" accept comment "nftfw:ipv6-loopback"
    }
    chain forward {
        type filter hook forward priority -300; policy drop;
        counter drop comment "nftfw:ipv6-emergency-deny"
    }
}
`
