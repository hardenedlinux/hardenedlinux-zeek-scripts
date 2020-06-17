#
# @TEST-EXEC: bro -C -r $TRACES/wikipedia.trace ../../../scripts/seen/udp %INPUT
# @TEST-EXEC: btest-diff intel.log

# @TEST-START-FILE intel.dat
#fields	indicator	indicator_type	meta.source	meta.desc	meta.url
224.0.0.252	Intel::ADDR	source1	this ip bad	http://some-data-distributor.com/1
# @TEST-END-FILE

# Load default seen scripts
@load frameworks/intel/seen
redef Intel::read_files += { "intel.dat" };
