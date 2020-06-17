# Version 1.0 (May 2019)
#
# Authors: Zer0d0y@天御实验室 (Zer0d0y@tianyulab.com)
#
# Copyright (c) 2019, 天御[攻防]实验室.
# All rights reserved.
# Licensed under the BSD 3-Clause license. 
#
# 支持Zeek Version v2.6.x
#
# Modified by hardenedlinux <2019-09-09 Mon>

@load base/files/extract

module VirusTotal;

export {
	redef enum Log::ID += { LOG };

	type Report: record {
        ts             : time        &log;
        fuid           : string      &log;
        mime_type      : string      &log &optional;
        sent_file      : bool        &log &default=F;
        scan_date      : time      	 &log &optional;
        permalink      : string      &log &default="";
        total_scanners : count       &log &default=0;
        hits           : set[string] &log &optional;
        av_names       : set[string] &log &optional;
    
	};

	# point the jp path (we going to use jq to parse VT_result to josn format)
	const jq: string = "/usr/local/bin/jq" &redef;

	## This is your VirusTotal API key and *must* be supplied for this plugin to work.
	const api_key = "" &redef;
	
	## Define the number of queries per minute that your API key can make.
	const queries_per_minute = 4 &redef;
	
	## Scan a file hash.  This is an async function and needs to 
	## to be called within a when statement.
	global scan_hash: function(f: fa_file, hash: string): Report;
}

# Help abide by the virus total query limits
global query_limiter: set[string] &create_expire=1min;

# event line(description: Input::EventDescription, tpe: Input::Event, r: KnownHashType)
# {
# print r;
# }
event zeek_init()
	{
	Log::create_stream(VirusTotal::LOG, [$columns=Report]);
# write to POSTGRESQL please see "https://github.com/hardenedlinux/Debian-GNU-Linux-Profiles/tree/master/NSM/INSTALL"
# Zeek.sh and analyzer.sh to know some install information.
# 	local filter: Log::Filter = [$name="postgres", $path="virtustotal", $writer=Log::WRITER_POSTGRESQL, $config=table([
# "dbname"]="testdb",["hostname"]="localhost user=myuser password=mypass",["port"]="5432")];
#     Log::add_filter(VirusTotal::LOG, filter);

   # Input::add_event([$source="SELECT ts,hash FROM known_hash;", $name="postgres", $fields=KnownHashType, $ev=line, $want_record=T,
   #  $reader=Input::READER_POSTGRESQL,
   #  $config=table(["dbname"]="testdb",["hostname"]="localhost user=myuser password=mypass",["port"]="5432")]); 

	}

function VirusTotal::parse_result(report: Report, result: string)
	{
    report$hits     = set();
    report$av_names = set();
	
	# I'm parsing JSON this way.  Kill me now.
	
	local parts = split_string(result, /( ?\{|\}, )/);
	#local top = split_string(result,/\}\},/);

	# parse VT_API-result to  virustotal_result.json file
	local jq_result = Exec::Command($cmd=fmt("echo '%s' | %s '.' >> virustotal_result.json", result,jq));
	
	for ( i in parts )
		{
		if ( /\"detected\": true/ in parts[i] )
			{
			local hit_parts = split_string(parts[i], /(result\": \"|\", \"update)/);
			local av = gsub(parts[i-1], /[\":]/, "");
			add report$hits[av];
			add report$av_names[hit_parts[1]];
			}
		if ( /permalink/ in parts[i] )
			{
			local scan_parts = split_string(parts[i], /\"/);
			for ( part_i in scan_parts )
				{
				if ( "scan_date" == scan_parts[part_i] )
					{
					report$scan_date = strptime("%Y-%m-%d %H:%M:%S", scan_parts[part_i+2]);
					}
				else if ( "permalink" == scan_parts[part_i] )
					{
					report$permalink = scan_parts[part_i+2];
					}
				else if ( "total" == scan_parts[part_i] )
					{
					report$total_scanners = to_count(gsub(scan_parts[part_i+1], /[^0-9]/, ""));
					}
				}
			}
		}
}


function VirusTotal::scan_hash(f: fa_file, hash: string): Report
	{
	if ( api_key != "" &&
	     |query_limiter| < queries_per_minute )
		{
		local addl = fmt("--data resource=%s --data apikey=%s", hash, api_key);
		local r = ActiveHTTP::Request($url="https://www.virustotal.com/vtapi/v2/file/report",
		                              $addl_curl_args=addl,
		                              $method="POST");
		
		return when ( local result = ActiveHTTP::request(r) )
			{
			local report = Report($ts   = network_time(),
			                      $fuid = f$id);
			if ( f$info?$mime_type )
				{
				report$mime_type = f$info$mime_type;
				}
			parse_result(report, result$body);
			if (report$total_scanners != 0)
				{
				Log::write(LOG, report);
				return report;
				}
			}
		}
	}
