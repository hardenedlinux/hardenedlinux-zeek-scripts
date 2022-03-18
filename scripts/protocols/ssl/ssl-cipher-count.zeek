# This script calculates the percentage of the use of the different
# TLS cipher suites for each host in the local network.
# Original Scirpt:https://github.com/0xxon/bro-sumstats-counttable
# modified by GTrunsec
@load base/protocols/ssl
@load packages/zeek-sumstats-counttable

module SSLCiphers;

export {
	redef enum Log::ID += {
		LOG
	};

	type Info: record {
		ts: time &log &default=network_time();
		resp_h: addr &log;
		cipher: string &log;
		percent: double &log;
		connections: count &log;
	};

	## The frequency of logging the stats collected by this script.
	const epoch_interval = 3 secs &redef;

	## Event that can be handled to access the Info record as it is sent to the
	## logging framework
	global log_ciphers: event(rec: Info);
}

event zeek_init()
{
	Log::create_stream(LOG, [
	    $columns=Info,
	    $ev=log_ciphers,
	    $path="ssl-ciphers"]);

	local r1: SumStats::Reducer = [
	    $stream="ciphers.conns",
	    $apply=set(SumStats::SUM)];
	local r2: SumStats::Reducer = [
	    $stream="ciphers.ciphers",
	    $apply=set(SumStats::COUNTTABLE)];

	SumStats::create([
	    $name="ciphers",
	    $epoch=epoch_interval,
	    $reducers=set(r1, r2),
	    $epoch_result (ts: time, key: SumStats::Key, result: SumStats::Result) = {
		# both of these always have to be in the result set
		if ( "ciphers.conns" !in result )
			return;
		if ( "ciphers.ciphers" !in result )
			return;

		local hits = result["ciphers.conns"]$sum;
		local ciphers = result["ciphers.ciphers"]$counttable;

		for ( cipher in ciphers ) {
			local line: Info = [
			    $resp_h=key$host,
			    $cipher=cipher,
			    $connections=ciphers[cipher],
			    $percent=( ciphers[cipher] + 0.0 ) / hits];
			Log::write(LOG, line);
		}
	}]);
}

event ssl_client_hello(c: connection, version: count, record_version: count,
    possible_ts: time, client_random: string, session_id: string,
    ciphers: index_vec, comp_methods: index_vec)

{
	#if (!Site::is_local_addr(c$id$resp_h))
	#	return;

	SumStats::observe("ciphers.conns", [$host=c$id$resp_h], [ ]);

	for ( i in ciphers )
		local cipher_str = SSL::cipher_desc[ciphers[i]];

	SumStats::observe("ciphers.ciphers", [$host=c$id$resp_h], [$str=cipher_str]);
}
