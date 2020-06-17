@load base/frameworks/logging/main.bro
function dns_fuc(id: Log::ID, path: string, rec: DNS::Info) : string
{
if ( rec?$qtype_name && rec$qtype_name == "NB") {
  return  "dns-netbios";
  }
return "dns-minimal";
}      
event zeek_init()
{
Log::remove_default_filter(DNS::LOG);
Log::add_filter(DNS::LOG, [$name="new-default",
$include=set("ts","id.orig_h","query"),
$path_func=dns_fuc]);
}