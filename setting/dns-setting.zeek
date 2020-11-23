@load ../scripts/protocols/dns/top_dns.zeek

redef TopDNS::records += {"MX"};
redef TopDNS::logging_interval = 1hr;
