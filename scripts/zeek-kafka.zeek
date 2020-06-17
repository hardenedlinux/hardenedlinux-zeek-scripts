@load /usr/local/zeek/lib/zeek/plugins/APACHE_KAFKA/scripts/Apache/Kafka
@load /usr/local/zeek/lib/zeek/plugins/mitrecnd_HTTP2/scripts/http2
@load ./protocols/
@load policy/misc/stats.zeek
@load policy/protocols/conn/known-services.zeek
@load policy/protocols/mqtt
@load ./files
redef Kafka::topic_name = "";
redef Kafka::tag_json = T;


redef Kafka::kafka_conf = table(
["metadata.broker.list"] = "localhost:9092"
# SASL_SSL configuration
# ["metadata.broker.list"] = "10.220.170.120:29091,10.220.170.121:2901",
# ["client.id"] = "Broker-1",
# ["security.protocol"] = "SASL_SSL",
# ["ssl.ca.location"] = "/data/kafka-ca/ca-cert",
# ["ssl.certificate.location"] = "/data/kafka-ca/kafka.client.pem",
# ["ssl.key.location"] = "/data/kafka-ca/kafka.client.key",
# ["ssl.key.password"] = "zeek@123",
# ["sasl.kerberos.keytab"] = "/data/kafka-ca/metron.headless.keytab",
# ["sasl.kerberos.principal"] = "metron@EXAMPLE.COM"
);

event zeek_init() &priority=-10
{

#VirusTotal::LOG
local filter_virus_total: Log::Filter = [
  $name = "virustotal",
  $writer = Log::WRITER_KAFKAWRITER,
  $path = "zeek-virustotal"
];
Log::add_filter (VirusTotal::LOG, filter_virus_total);
# Known::hash
local filter_known_hash: Log::Filter = [
  $name = "known_hash",
  $writer = Log::WRITER_KAFKAWRITER,
  $path = "zeek-known_hash"
];
Log::add_filter (Known::HASH_LOG, filter_known_hash);

# Known::hosts
local filter_known_hosts: Log::Filter = [
    $name = "known_hosts",
    $writer = Log::WRITER_KAFKAWRITER,
    $path = "zeek-known_hosts"
];
Log::add_filter (Known::HOSTS_LOG, filter_known_hosts);

# Known::domains
local filter_known_domains: Log::Filter = [
    $name = "known_domains",
    $writer = Log::WRITER_KAFKAWRITER,
    $path = "zeek-known_domains"
];
Log::add_filter (Known::DOMAIN_LOG, filter_known_domains);

#smb_mapping
local filter_smb_mapping: Log::Filter = [
    $name = "filter_smb_mapping",
    $writer = Log::WRITER_KAFKAWRITER,
    $path = "zeek-smb_mapping"
];
Log::add_filter(SMB::MAPPING_LOG, filter_smb_mapping);
#smb_files
local filter_smb_files: Log::Filter = [
    $name = "filter_smb_files",
    $writer = Log::WRITER_KAFKAWRITER,
    $path = "zeek-smb_files"
];
Log::add_filter(SMB::FILES_LOG, filter_smb_files );

#files
local kafka_files: Log::Filter = [
    $name = "kafka_files",
    $writer = Log::WRITER_KAFKAWRITER,
    $path = "zeek-files"
];
Log::add_filter(Files::LOG, kafka_files);


#files_identified
local filter_files: Log::Filter = [
    $name = "filter_files",
    $writer = Log::WRITER_KAFKAWRITER,
    $path = "zeek-files_identified"
];
Log::add_filter(Files::LOG, filter_files );
#known_services
local filter_known_services: Log::Filter = [
    $name = "filter_known_services",
    $writer = Log::WRITER_KAFKAWRITER,
    $path = "zeek-known_services"
];
Log::add_filter(Known::SERVICES_LOG, filter_known_services );
#SOCKS
local filter_socks: Log::Filter = [
    $name = "kafka-socks",
    $writer = Log::WRITER_KAFKAWRITER,
    $path = "zeek-socks"
];
Log::add_filter(SOCKS::LOG, filter_socks );
#	SNMP
local filter_SNMP: Log::Filter = [
    $name = "kafka_snmp",
    $writer = Log::WRITER_KAFKAWRITER,
    $path = "zeek-snmp"
];
Log::add_filter(SNMP::LOG, filter_SNMP );
#DNP3
local filter_dnp3: Log::Filter = [
    $name = "dnp3",
    $writer = Log::WRITER_KAFKAWRITER,
    $path = "zeek-dnp3"
];
Log::add_filter(DNP3::LOG, filter_dnp3 );
#FTP
local filter_FTP: Log::Filter = [
    $name = "kafka-ftp",
    $writer = Log::WRITER_KAFKAWRITER,
    $path = "zeek-ftp"
];
Log::add_filter(FTP::LOG, filter_FTP );
#MySQL
local filter_mysql: Log::Filter = [
    $name = "kafka-mysql",
    $writer = Log::WRITER_KAFKAWRITER,
    $path = "zeek-mysql"
];
Log::add_filter(mysql::LOG,filter_mysql );
#Status
local filter_stats: Log::Filter = [
    $name = "kafka-status",
    $writer = Log::WRITER_KAFKAWRITER,
    $path = "zeek-stats"
];
Log::add_filter(Stats::LOG, filter_stats );
#Broker
local filter_broker: Log::Filter = [
    $name = "broker",
    $writer = Log::WRITER_KAFKAWRITER,
    $path = "zeek-broker"
];
Log::add_filter(Broker::LOG, filter_broker );
#intel
local filter_intel: Log::Filter = [
    $name = "kafka-intel",
    $writer = Log::WRITER_KAFKAWRITER,
    $path = "zeek-intel"
];
Log::add_filter(Intel::LOG, filter_intel);
##x509
local filter_x509: Log::Filter = [
    $name = "kafka-x509",
    $writer = Log::WRITER_KAFKAWRITER,
    $path = "zeek-x509"
];
Log::add_filter(X509::LOG, filter_x509 );
##ssl
local filter_ssl: Log::Filter = [
    $name = "kafka_ssl",
    $writer = Log::WRITER_KAFKAWRITER,
    $path = "zeek-zeek-ssl"
];
Log::add_filter(SSL::LOG, filter_ssl );
##ssh-status
local filter_ssh: Log::Filter = [
    $name = "ssh-status",
    $writer = Log::WRITER_KAFKAWRITER,
    $path = "zeek-auth_ssh"
];
Log::add_filter(HSSH::LOG, filter_ssh );
##Hash-fuzzing
##top_dns
local filter_top_dns: Log::Filter = [
    $name = "top-dns",
    $writer = Log::WRITER_KAFKAWRITER,
    $path = "zeek-top_dns"
];
Log::add_filter(TopDNS::LOG,filter_top_dns );

#MQTT::subscribe
local filter_mqtt_subscribe : Log::Filter = [
    $name = "mqtt_subscribe",
    $writer = Log::WRITER_KAFKAWRITER,
    $path = "zeek-mqtt_subscribe"
];
Log::add_filter(MQTT::SUBSCRIBE_LOG, filter_mqtt_subscribe);

#MQTT::publish
local filter_mqtt_publish : Log::Filter = [
    $name = "mqtt_publish",
    $writer = Log::WRITER_KAFKAWRITER,
    $path = "zeek-mqtt_publish"
];
Log::add_filter(MQTT::PUBLISH_LOG, filter_mqtt_publish);

#MQTT::connect
local filter_mqtt_connect : Log::Filter = [
    $name = "mqtt_connect",
    $writer = Log::WRITER_KAFKAWRITER,
    $path = "zeek-mqtt_connect"
];
Log::add_filter(MQTT::CONNECT_LOG, filter_mqtt_connect);

## Http2
local filter_http2: Log::Filter = [
    $name = "http2",
    $writer = Log::WRITER_KAFKAWRITER,
    $path = "zeek-http2"
];
Log::add_filter(HTTP2::LOG, filter_http2 );


##protocols-stats-resp
# local protocols_resp: Log::Filter = [
#     $name = "protocols-resp",
#     $writer = Log::WRITER_KAFKAWRITER,
#     $path = "zeek-protocols-resp"
# ];
# Log::add_filter(ProtocolStats::RESP, protocols_resp);

##protocols-stats-orig
# local protocols_orig: Log::Filter = [
#     $name = "protocols-o",
#     $writer = Log::WRITER_KAFKAWRITER,
#     $path = "zeek-protocols-orig"
# ];
# Log::add_filter(ProtocolStats::ORIG, protocols_orig);

##TrafficsSummary::LOG
local resp_summary: Log::Filter = [
    $name = "resp-summary",
    $writer = Log::WRITER_KAFKAWRITER,
    $path = "zeek-resp-summary"
];
Log::add_filter(RespTrafficSummary::LOG, resp_summary);


##ssl_ciphers
local ssl_ciphers: Log::Filter = [
    $name = "ssl-ciphers",
    $writer = Log::WRITER_KAFKAWRITER,
    $path = "zeek-ssl-ciphers"
];
Log::add_filter(SSLCiphers::LOG, ssl_ciphers );

#UniqueMacs::LOG
local conn_macs: Log::Filter = [
    $name = "conn_macs",
    $writer = Log::WRITER_KAFKAWRITER,
    $path = "zeek-unique-macs"
];
Log::add_filter(UniqueMacs::LOG,conn_macs );
# handles HTTP
local http_filter: Log::Filter = [
    $name = "kafka-http",
    $writer = Log::WRITER_KAFKAWRITER,
    $path = "zeek-http"
];
Log::add_filter(HTTP::LOG, http_filter);

#handles software
local software_filter: Log::Filter = [
    $name = "kafka-software",
    $writer = Log::WRITER_KAFKAWRITER,
    $path = "zeek-software"
];
Log::add_filter(Software::LOG, software_filter);

#SMTP
local smtp_filter: Log::Filter = [
    $name = "kafka-smtp",
    $writer = Log::WRITER_KAFKAWRITER,
    $path = "zeek-smtp"
];
Log::add_filter(SMTP::LOG,smtp_filter );

#IRC
local irc_filter: Log::Filter = [
    $name = "kafka-irc",
    $writer = Log::WRITER_KAFKAWRITER,
    $path = "zeek-irc"
];
Log::add_filter(IRC::LOG, irc_filter );

#handles pe
local pe_filter: Log::Filter = [
    $name = "kafka-pe",
    $writer = Log::WRITER_KAFKAWRITER,
    $path = "zeek-pe"
];
Log::add_filter(PE::LOG, pe_filter );
#handles dhcp
local dhcp_filter: Log::Filter = [
    $name = "kafka-dhcp",
    $writer = Log::WRITER_KAFKAWRITER,
    $path = "zeek-dhcp"
];
Log::add_filter(DHCP::LOG, dhcp_filter);

#handles ssh
local ssh_filter: Log::Filter = [
    $name = "kafka-ssh",
    $writer = Log::WRITER_KAFKAWRITER,
    $path = "zeek-ssh"
];
Log::add_filter(SSH::LOG, ssh_filter );

# handles conn
local Conn_filter: Log::Filter = [
    $name = "kafka-conn",
    $writer = Log::WRITER_KAFKAWRITER,
    $path = "zeek-conn"
];
Log::add_filter(Conn::LOG, Conn_filter );

# handles Notice
local Notice_filter: Log::Filter = [
    $name = "kafka-Notice",
    $writer = Log::WRITER_KAFKAWRITER,
    $path = "zeek-notice"
];
Log::add_filter(Notice::LOG, Notice_filter);

# handles DNS
local dns_filter: Log::Filter = [
    $name = "kafka-dns",
    $writer = Log::WRITER_KAFKAWRITER,
    $path = "zeek-dns"
];
Log::add_filter(DNS::LOG, dns_filter);


# top-metrics url
local conn_top_urls: Log::Filter = [
    $name = "conn_top_urls",
    $writer = Log::WRITER_KAFKAWRITER,
    $path = "zeek-top_urls"
];
Log::add_filter(TopMetrics::URLS, conn_top_urls);

# top-metrics url-talkes
local conn_top_talkers: Log::Filter = [
    $name = "conn_top_talkers",
    $writer = Log::WRITER_KAFKAWRITER,
    $path = "zeek-top_talkers"
];
Log::add_filter(TopMetrics::TALKERS, conn_top_talkers);

#UniqueHosts::LOG
local conn_host: Log::Filter = [
    $name = "conn_host",
    $writer = Log::WRITER_KAFKAWRITER,
    $path = "zeek-unique-host"
];
Log::add_filter(UniqueHosts::LOG, conn_host);


#ntlm
local kafka_ntlm: Log::Filter = [
    $name = "kafka_ntml",
    $writer = Log::WRITER_KAFKAWRITER,
    $path = "zeek-ntml"
];
Log::add_filter(NTLM::LOG, kafka_ntlm);




#ntp
local kafka_ntp: Log::Filter = [
    $name = "kafka_ntp",
    $writer = Log::WRITER_KAFKAWRITER,
    $path = "zeek-ntp"
];
Log::add_filter(NTP::LOG, kafka_ntp);



#dpd

local kafka_dpd: Log::Filter = [
    $name = "kafka_dpd",
    $writer = Log::WRITER_KAFKAWRITER,
    $path = "zeek-dpd"
];
Log::add_filter(DPD::LOG, kafka_dpd);


#weird
local kafka_weird: Log::Filter = [
    $name = "kafka_weird",
    $writer = Log::WRITER_KAFKAWRITER,
    $path = "zeek-werid"
];
Log::add_filter(Weird::LOG, kafka_weird);



#reporter
local kafka_reporter: Log::Filter = [
    $name = "kafka_reporter",
    $writer = Log::WRITER_KAFKAWRITER,
    $path = "zeek-reporter"
];
Log::add_filter(Reporter::LOG, kafka_reporter);
}
