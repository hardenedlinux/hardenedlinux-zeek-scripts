
@load ../../frameworks/countabble.zeek


module UniqueMacs;

export {

global watched_nets: set[subnet] = [ 10.0.0.0/8, 192.168.0.0/16 ] &redef;
global epoch: interval = 1hr &redef;

# Logging info
redef enum Log::ID += { LOG };

type Info: record {
  start_time: string &log;
  epoch: interval &log;
  net: string &log;
  mac_cnt: count &log;
  };

global log_conn_count: event(rec: Info);

}

event zeek_init()
  {
  
  Log::create_stream(UniqueMacs::LOG, [$columns=Info, $ev=log_conn_count, $path="unique-macs"]);

  local r1 = SumStats::Reducer($stream="unique.macs", $apply=set(SumStats::COUNTTABLE));
  SumStats::create([$name="unique.macs",
  $epoch=epoch,
  $reducers=set(r1),
  $epoch_result(ts: time, key: SumStats::Key, result: SumStats::Result) =
{
local r = result["unique.macs"];
local counttable = r$counttable;

for ( i in counttable )
  local rec = [$start_time= strftime("%c", r$begin), $epoch=epoch, $net=key$str, $mac_cnt=r$counttable[i]];
  Log::write(UniqueMacs::LOG, rec);

  }
]);
}

event DHCP::log_dhcp(rec: DHCP::Info) {


  if ( rec$assigned_addr in watched_nets ) {

    local net: subnet;
    
    for ( net in watched_nets ) { 

  if ( rec?$assigned_addr && (rec$assigned_addr in watched_nets )) {

      {
        SumStats::observe("unique.macs", [$str=fmt("%s",net)], [$str=rec$mac]);
      }

      }
    }
  }

}
