@load ../scripts/protocols/dns/top_dns.zeek
@load ../scripts/protocols/dns/dns-tunnels.zeek
@load ../scripts/protocols/dns/dyndns.zeek
@load ../scripts/protocols/dns/alexa
redef TopDNS::records += {
	"MX"
};
redef TopDNS::logging_interval = 1 hr;
redef TopDNS::use_trimmed_domain = T;

redef DNS_TUNNELS::request_count_threshold = 10;
redef DNS_TUNNELS::query_len_threshold = 27;
redef DNS_TUNNELS::percentage_of_num_count = 0.2;

redef DNS_TUNNELS::record_expiration = 5 min;
redef DNS_TUNNELS::check_timestamps = 1 hr;

redef Alexa::ignore_dns {
	"WORKGROUP",
	"DOMEX"
};
redef DynamicDNS::ignore_dyndns_fqdns { };
