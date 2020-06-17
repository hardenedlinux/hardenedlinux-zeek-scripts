# Copyright 2015 Reservoir Labs, Inc.
# All rights reserved.
# 
# Contributed by Bob Rotsted

#Modifid by hardenedlinux
module TrackDHCP;

export {
  global ip_to_mac: table[addr] of string  &write_expire=1day; 

redef record Conn::Info += {
  orig_mac: string &optional &log;
  resp_mac: string &optional &log;
  };
}

event DHCP::log_dhcp (rec: DHCP::Info) {
    if ( rec?$assigned_addr){

        ip_to_mac[rec$assigned_addr] = rec$mac;
        }
  }

event connection_state_remove (c: connection) { 
  if ( c$id$orig_h in TrackDHCP::ip_to_mac ) 
    c$conn$orig_mac = TrackDHCP::ip_to_mac[c$id$orig_h];
    
    if ( c$id$resp_h in TrackDHCP::ip_to_mac ) 
      c$conn$resp_mac = TrackDHCP::ip_to_mac[c$id$resp_h];
      }
