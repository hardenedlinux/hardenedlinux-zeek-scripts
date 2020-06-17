#source frome https://github.com/corelight/top-dns/blob/master/scripts/main.bro
@load base/utils/site
@load base/frameworks/sumstats
@load ../../frameworks/domain-tld/scripts
module TopDNS;

export {
	## How many of the top missing names should be logged.
	const top_k = 10 &redef;

	## How often the log should be written.
	const logging_interval = 15mins &redef;

	## If you would like to measure trimmed "effective domains".
	## This will take something like "www.google.co.uk" and only 
	## use "google.co.uk" as the measured value.
	const use_trimmed_domain = F &redef;

	## The records that should be tracked and logged.
	const records: set[string] = {
"A",
	"AAAA",
	"CNAME",
	} &redef;

## The log ID.
redef enum Log::ID += { LOG };

type Info: record {
	## Timestamp of when the data was finalized.
	ts:           time             &log;

	## Length of time that this Top measurement represents.
	ts_delta:     interval         &log;

	## The query type that this log line refers to.
	record_type:  string           &log;

	## The top queries being performed.
	top_queries:  vector of string &log;

	## The estimated counts of each of the top queries.
	top_counts:   vector of count  &log;

	## The estimated distance from the true value for each reported value.
	top_epsilons: vector of count  &log;
	};
}

event zeek_init() &priority=5
	{
	Log::create_stream(TopDNS::LOG, [$columns=Info, $path="top_dns"]);

	local r1 = SumStats::Reducer($stream="top-dns-name", 
$apply=set(SumStats::TOPK), 
$topk_size=top_k*10);
SumStats::create([$name="find-top-queries",
$epoch=logging_interval,
$reducers=set(r1),
$epoch_result(ts: time, key: SumStats::Key, result: SumStats::Result) =
{
local r = result["top-dns-name"];
local s: vector of SumStats::Observation;
s = topk_get_top(r$topk, top_k);

local top_queries = string_vec();
local top_counts = index_vec();
local top_epsilons = index_vec();
local i = 0;
for ( element in s ) 
	{
	top_queries[|top_queries|] = s[element]$str;
	top_counts[|top_counts|] = topk_count(r$topk, s[element]);
	top_epsilons[|top_epsilons|] = topk_epsilon(r$topk, s[element]);

	if ( ++i == top_k )
	  break;
	  }

	Log::write(TopDNS::LOG, [$ts=ts, 
$ts_delta=logging_interval, 
$record_type=key$str,
$top_queries=top_queries,
$top_counts=top_counts, 
$top_epsilons=top_epsilons]);
}
]);
}

event DNS::log_dns(rec: DNS::Info)
	{
	if ( rec?$query && rec?$qtype &&
	  rec$qtype_name in records &&
	! Site::is_local_name(rec$query) )
{
local q = use_trimmed_domain ? DomainTLD::effective_domain(rec$query) : rec$query;
SumStats::observe("top-dns-name", [$str=rec$qtype_name], [$str=q]);
}
}