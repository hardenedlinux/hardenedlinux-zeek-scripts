#
# @TEST-EXEC: bro -C -r $TRACES/wikipedia.trace ../../../scripts/seen/conn-tcp %INPUT
# @TEST-EXEC: btest-diff intel.log

# @TEST-START-FILE intel.dat
#fields	indicator	indicator_type	meta.source	meta.desc	meta.url
141.142.220.118:49997	Intel::CONN_TCP	source1	bad	http://some-data-distributor.com/1
208.80.152.2:80	Intel::CONN_TCP	source1	also bad	http://some-data-distributor.com/1
141.142.220.118	Intel::ADDR	source1	bad ip	http://some-data-distributor.com/1
208.80.152.2	Intel::ADDR	source1	also bad ip	http://some-data-distributor.com/1
# @TEST-END-FILE

# Load default seen scripts
@load frameworks/intel/seen
redef Intel::read_files += { "intel.dat" };
