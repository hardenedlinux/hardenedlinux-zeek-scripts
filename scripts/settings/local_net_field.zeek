
##! TODO // Broker sync link to vlan-info

# redef vlanlist += {
# [100] = [$description="north",$ipv4net=10.2.0.0/24,$ipv6net=[2001:0468:1f07:000b::]/64,$location="north",field = "#1 jiaoxue"],
# [101] = [$description="south",$ipv4net=10.12.0.0/24,$ipv6net=[2001:0468:1f07:000c::]/64,$location="south",field = "#2 jiaoxue"],
# [102] = [$description="west",$ipv4net=10.16.0.0/24,$ipv6net=[2001:0468:1f07:000d::]/64,$location="west",field = "#3 jiaoxue"],
# [103] = [$description="east",$ipv4net=10.10.0.0/24,$ipv6net=[2001:0468:1f07:f00e::]/64,$location="east",field = "#4 jiaoxue"]
# }
@load ../scripts/protocols/conn/known-hosts-with-dns.zeek

redef Site::local_nets += { 87.0.0.0/8 };

#redef Known::use_host_store = F;