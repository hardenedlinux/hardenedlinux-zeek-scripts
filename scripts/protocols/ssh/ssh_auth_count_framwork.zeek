@load ../../frameworks/countabble.zeek

module HSSH;

export {
  redef enum Log::ID += { LOG };

  const epoch_interval = 10min &redef;

  type Info: record {
    host : addr &log;
    failed_count :count &log;
    sucess_count :count &log;
    };

  global log_mqtt: event(rec: Info);

  }
event zeek_init()
	{
	Log::create_stream(HSSH::LOG, [$columns=Info, $ev=log_mqtt, $path="auth_ssh"]);

	local r1 = SumStats::Reducer($stream="failed.ssh", $apply=set(SumStats::COUNTTABLE));
	local r2 = SumStats::Reducer($stream="sucess.ssh", $apply=set(SumStats::COUNTTABLE));

	SumStats::create([$name="ssh-connect",
		$epoch=epoch_interval,
	$reducers=set(r1,r2),
		$epoch_result(ts: time, key: SumStats::Key, result: SumStats::Result) =
	{
	if ( "failed.ssh" !in result )
		return;
		local counttable = result["failed.ssh"]$counttable;
		local sucesscount = result["sucess.ssh"]$counttable;
		for ( i in counttable )
			for (k in sucesscount)
				Log::write(HSSH::LOG, [$host=key$host,$failed_count=counttable[i],$sucess_count=sucesscount[k]]);
		  }]);

	}

event ssh_auth_failed(c:connection)
  {
  local id = c$ssh$client;
  SumStats::observe("failed.ssh", [$host=c$id$resp_h], [$str=id]);
  }
 event ssh_auth_successful(c: connection, auth_method_none: bool)
  {
   local id = c$ssh$client;
  SumStats::observe("sucess.ssh", [$host=c$id$resp_h], [$str=id]);
  }
