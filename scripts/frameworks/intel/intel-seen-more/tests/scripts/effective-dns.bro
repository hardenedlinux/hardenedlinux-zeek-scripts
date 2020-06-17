#
# @TEST-EXEC: bro -C -r $TRACES/wikipedia.trace %INPUT ../../../scripts/seen/effective-dns
# @TEST-EXEC: btest-diff intel.log

# @TEST-START-FILE intel.dat
#fields	indicator	indicator_type	meta.source	meta.desc	meta.url
wikimedia.org	Intel::DOMAIN	source1	this domain bad	http://some-data-distributor.com/1
meta.wikimedia.org	Intel::DOMAIN	source1	this domain bad	http://some-data-distributor.com/1
wikimedia.org	Intel::EFFECTIVE_DOMAIN	source1	this domain bad	http://some-data-distributor.com/1
# @TEST-END-FILE

@load packages

# Load default seen scripts
@load frameworks/intel/seen
redef Intel::read_files += { "intel.dat" };
