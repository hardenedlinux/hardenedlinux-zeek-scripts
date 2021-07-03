module CVE_2017_12240.;
export {
    redef enum Notice::Type += {
		LARGE_DHCP_PACKET
	};

    const dhcp_pkt_threshold = 301 &redef;
}
