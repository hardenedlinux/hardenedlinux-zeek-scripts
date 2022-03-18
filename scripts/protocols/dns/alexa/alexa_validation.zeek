@load base/protocols/dns
@load base/frameworks/notice
@load base/frameworks/input
@load base/frameworks/sumstats
@load packages/domain-tld

module Alexa;

export {
	redef enum Notice::Type += {
		Alexa::DNS_Not_In_Alexa_1M
	};

	# path to alexa 1m file
	#const alexa_file = "/home/gtrun/project/hardenedlinux-zeek-script/scripts/protocols/dns/alexa/top-1m.txt" &redef;
	const alexa_file = "top-1m.txt" &redef;

	# hosts to ignore
	# global DNS::log_dns: event (rec: DNS::Info);
	option ignore_dns: set[string] = { } &redef;
	global alexa_table: set[string] = set();
}

# Record for domains in file above
type Idx: record {
	domain: string;
};

# Table to store list of domains in file above
global missed_alexa_dns_count: double;

event zeek_init()
{
	Input::add_table([
	    $source=alexa_file,
	    $mode=Input::REREAD,
	    $name="alexa_table",
	    $idx=Idx,
	    $destination=alexa_table]);
	local r1 = SumStats::Reducer(
	    $stream="missed_alexa_dns",
	    $apply=set(SumStats::SUM));
	SumStats::create([
	    $name="missed_alexa_dns",
	    $epoch=10 min,
	    $reducers=set(r1), # Provide a threshold.
	#$threshold = 5.0,
	# Provide a callback to calculate a value from the result
	# to check against the threshold field.

	# Provide a callback for when a key crosses the threshold.
	$epoch_result (ts: time, key: SumStats::Key, result: SumStats::Result) = {
		#	print fmt("%.0f",result["missed_alexa_dns"]$sum);

		if ( "missed_alexa_dns" !in result )
			return;
		missed_alexa_dns_count = result["missed_alexa_dns"]$sum;
	}]);
}
event DNS::log_dns(rec: DNS::Info)

{
	# Do not process the event if no query exists
	if ( ! rec?$query )
		return;

	# If necessary, clean the query so that it can be found in the list of Alexa domains

	local not_ignore = T;
	for ( dns in ignore_dns ) {
		if ( dns in rec$query )
			not_ignore = F;
	}
	local get_domain = DomainTLD::effective_domain(rec$query);
	# Check if the query is not in the list of Alexa domains
	if ( ! ( get_domain in alexa_table )
	    && ! ( rec$query in alexa_table )
	    && not_ignore ) {
		# Prepare the sub-message for the notice
		# Include the domain queried in the sub-message
		local sub_msg = fmt("%s", DomainTLD::effective_domain(rec$query));
		SumStats::observe("missed_alexa_dns", [
		    $host=rec$id$orig_h], SumStats::Observation(
		    $num=1));

		# Generate the notice
		# Includes the connection flow, host intiating the lookup, domain queried, and query answers (if available)
		##! $msg=fmt("%s unknown domain. missed_count %0.f", rec$id$orig_h,missed_alexa_dns_count),
		##! FIXME : Need to fix bug that value used but not set
		NOTICE([
		    $note=Alexa::DNS_Not_In_Alexa_1M,
		    $msg=fmt("%s <-unknown domain", rec$id$orig_h),
		    $sub=sub_msg,
		    $id=rec$id,
		    $uid=rec$uid,
		    $identifier=cat(rec$id$orig_h, rec$query)]);
	}
}
