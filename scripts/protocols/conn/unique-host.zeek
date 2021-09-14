# Written by Bob Rotsted
# Copyright Reservoir Labs, 2014.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

# Modified by hardenedlinux
module UniqueHosts;
@load packages/zeek-sumstats-counttable

export {
    global watched_nets: set[subnet] = [ 10.0.0.0/8, 192.168.0.0/16 ] &redef;
    global epoch: interval = 1hr &redef;

    # Logging info
    redef enum Log::ID += { LOG };

    type Info: record {
      start_time: string &log;
      epoch: interval &log;
      net: string &log;
      ip_cnt: count &log;
      };

    global log_conn_count: event(rec: Info);
}

event zeek_init()
  {
  #local rec: UniqueHosts::Info;
  Log::create_stream(UniqueHosts::LOG, [$columns=Info, $ev=log_conn_count, $path="unique-host"]);

  local r1 = SumStats::Reducer($stream="unique.hosts", $apply=set(SumStats::COUNTTABLE));
  SumStats::create([$name="unique.hosts",
  $epoch=epoch,
  $reducers=set(r1),
  $epoch_result(ts: time, key: SumStats::Key, result: SumStats::Result) =
{
local r = result["unique.hosts"];
local counttable = r$counttable;

for ( i in counttable )

  local rec = [$start_time= strftime("%c", r$begin), $epoch=epoch, $net=key$str, $ip_cnt=r$counttable[i]];
  Log::write(UniqueHosts::LOG, rec);

  }
]);
}

event connection_established(c: connection)
  {

  if ( c$id$orig_h in watched_nets || c$id$resp_h in watched_nets ) {

    local net: subnet;

    for ( net in watched_nets ) {

      if ( c$id$orig_h in net ) {
        SumStats::observe("unique.hosts", [$str=fmt("%s",net)], [$str=fmt("%s",c$id$orig_h)]);
        }

      if ( c$id$resp_h in net ) {
        SumStats::observe("unique.hosts", [$str=fmt("%s",net)], [$str=fmt("%s",c$id$orig_h)]);
        }
      }
    }

  }
