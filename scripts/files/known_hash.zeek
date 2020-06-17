@load base/frameworks/cluster
@load frameworks/files/hash-all-files

module Known;

export {
	redef enum Log::ID += { HASH_LOG };
	
	type HashInfo: record {

		ts:           	 	time   		&log;

		host:           	addr   		&log;

	  	hash: 			string 		&log 	&optional;

known_file_types : string       &log    &optional;
		# found_in_alexa:		bool 		&log;

		# found_dynamic:		bool 		&log;
	};
	

	## Toggles between different implementations of this script.
	## When true, use a Broker data store, else use a regular Zeek set
	## with keys uniformly distributed over proxy nodes in cluster
	## operation.
	const use_hash_store = T &redef;

    global hash_store: Cluster::StoreInfo;

	## The Broker topic name to use for :zeek:see:`Known::hash_store`.
	const hash_store_name = "zeek/known/hash" &redef;

	## This also changes the interval at which hash get logged.
	option hash_store_expiry = 30day;

	## The timeout interval to use for operations against
	option hash_store_timeout = 15sec;

    global hashes: set[string] &create_expire=1day &redef;
	global stored_hash: set[string];
	## Event that can be handled to access the loggable record as it is sent
	## on to the logging framework.
	global Known::log_known_hash: event(rec: HashInfo);
	global Known::known_hash_add: event(info: HashInfo);

	const match_file_types = /application\/x-dosexec/ |
                             /application\/x-executable/ &redef;
}


function known_relay_topic(): string{
	local rval = Cluster::rr_topic(Cluster::proxy_pool, "known_rr_key");

	if ( rval == "" )
		# No proxy is alive, so relay via manager instead.
		return Cluster::manager_topic;
	return rval;
}

event zeek_init()
	{
	if ( ! Known::use_hash_store )
		return;

	Known::hash_store = Cluster::create_store(Known::hash_store_name);
	}

event Known::hash_found(info: HashInfo)
    {
	if ( ! Known::use_hash_store )
		return;
@if ( ! Cluster::is_enabled() || Cluster::local_node_type() == Cluster::MANAGER )

	when ( local r = Broker::put_unique(Known::hash_store$store, info$hash,
	T, Known::hash_store_expiry) )
		{
		if ( r$status == Broker::SUCCESS )
			{
			if (info?$hash && r?$result as bool)
				local hash_data = fmt("%s",info$hash as string);
                add Known::hashes[hash_data];
			    Log::write(Known::HASH_LOG, info);
			}
		else
            Reporter::error(fmt("%s: data store put_unique failure",
			Known::hash_store_name));
		}
	timeout Known::hash_store_timeout
		{
		# Can't really tell if master store ended up inserting a key.
		Log::write(Known::HASH_LOG, info);
		}
		@if ( Cluster::local_node_type() == Cluster::MANAGER)
			# essentially, we're waiting for the asynchronous Broker calls to finish populating
			# the manager's Known::stored_hosts and then sending the table to the workers all at once
			schedule 30sec {Known::send_known()};
		@endif
	@endif	
    }

event known_hash_add(info: HashInfo)
	{
	if ( Known::use_hash_store )
		return;

	if ( [info$hash] in Known::hashes )
		return;

	@if ( ! Cluster::is_enabled() ||
	Cluster::local_node_type() == Cluster::PROXY ||
	Cluster::local_node_type() == Cluster::MANAGER )
	Broker::publish(Cluster::worker_topic, Known::known_hash_add, info$hash);
	@else
		add Known::hash[info$hash];
	@endif
	}

event Known::hash_found(info: HashInfo)
	{
	if ( Known::use_hash_store )
		return;

	if ( [info$hash] in Known::hashes )
		return;
	@if ( Cluster::local_node_type() == Cluster::WORKER )
	Broker::publish(known_relay_topic, info$hash, known_hash_add, info);
	@endif
	}



event Known::manager_to_workers(myhash: set[string]){
	for (hash in myhash){
		add Known::hashes[hash];
	}
}

event Known::send_known(){
	Broker::publish(Cluster::worker_topic,Known::manager_to_workers,Known::stored_hash);
	# kill it, no longer needed
	Known::stored_hash = set();

}


event zeek_init()
	{
	Log::create_stream(Known::HASH_LOG, [$columns=HashInfo, $ev=log_known_hash, $path="known_hash"]);
# 	local filter: Log::Filter = [$name="known_hash", $path="known_hash", $writer=Log::WRITER_POSTGRESQL, $config=table([
# "dbname"]="testdb",["hostname"]="localhost user=myuser password=mypass",["port"]="5432")];
#     Log::add_filter(HASH_LOG, filter);
	}


event file_hash(f: fa_file, kind: string, hash: string)
    {
        local downloader: addr = 0.0.0.0;

        for ( host in f$info$rx_hosts )
	if (f$info?$mime_type && (match_file_types in f$info$mime_type))
        {
            downloader = host;
            local info = HashInfo($ts = network_time(), $host = downloader, $hash = hash, $known_file_types = f$info$mime_type);
            event Known::hash_found(info);
            @if ( Cluster::is_enabled() && Cluster::local_node_type() == Cluster::WORKER )
                Broker::publish(Cluster::manager_topic,Known::hash_found,[$ts = network_time(), $host = downloader, $hash = hash,  $known_file_types = f$info$mime_type]);				
            @endif
        }
    }
