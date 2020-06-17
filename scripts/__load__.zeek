@load  packages/hardenedlinux-zeek-script/protocols/conn                                                                                 
@load  packages/hardenedlinux-zeek-script/protocols/dns
@load  packages/hardenedlinux-zeek-script/protocols/http
@load  packages/hardenedlinux-zeek-script/protocols/smtp
@load  packages/hardenedlinux-zeek-script/protocols/ssh
@load  packages/hardenedlinux-zeek-script/protocols/ssl
@load  packages/hardenedlinux-zeek-script/protocols/rdp
@load  packages/hardenedlinux-zeek-script/frameworks/bif
@load  packages/hardenedlinux-zeek-script/files

@load ./frameworks/input
@load ./log-passwords.zeek


# @load ./vlan-info                                                                                                                       
# @load ./frameworks/software/__load__.zeek
# @load ./protocols/smtp
# @load ./protocols/ssh
# @load ./protocols/rdp
# @load ./protocols/ssl

# @load ./log-passwords.zeek
# @load ./zeek-kafka.zeek
# @load ./frameworks/notice/mutlti.zeek
