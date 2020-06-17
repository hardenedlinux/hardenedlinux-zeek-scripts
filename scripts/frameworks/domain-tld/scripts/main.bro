##! This module contains some convenience mechanisms for extracting TLDs
##! and domains from fully qualified domain names using data available
##! from Mozilla which can be found here:
##!   https://publicsuffix.org/list/effective_tld_names.dat
##!
##! Author: Seth Hall <seth@icir.org>

module DomainTLD;

export {
	## This function uses a built in list of "effective" TLDs pulled from 
	## the list that Mozilla maintains to take any arbitrary domain and 
	## find the "effective TLD".  For example, "www.google.co.uk" is turned
	## into "co.uk".
	##
	## domain: The domain to find the effective TLD within.
	## 
	## Returns: The "effective TLD" string.
	global effective_tld: function(domain: string): string;
	
	## This function uses a built in list of "effective" TLDs pulled from 
	## the list that Mozilla maintains to take any arbitrary domain and 
	## find the "effective domain".  For example, "www.google.co.uk" is turned
	## into "google.co.uk".
	##
	## domain: The FQDN to find the effective domain within.
	## 
	## Returns: The "effective domain" string.
	global effective_domain: function(domain: string): string;
	
	## This function can strip domain portions from domain names efficiently.
	##
	## domain: The domain to strip domain portions from.
	## 
	## depth: The number of domain portions that you would like to keep.
	##
	## Returns: The domain with the requested number of domain components remaining.
	global zone_by_depth: function(domain: string, depth: count): string;
}

const effective_tlds_1st_level: pattern = /DEFINED_IN_SEPARATE_FILE/ &redef;
const effective_tlds_2nd_level: pattern = /DEFINED_IN_SEPARATE_FILE/ &redef;
const effective_tlds_3rd_level: pattern = /DEFINED_IN_SEPARATE_FILE/ &redef;
const effective_tlds_4th_level: pattern = /DEFINED_IN_SEPARATE_FILE/ &redef;

const effective_tld_pattern: pattern    = /DEFINED_IN_SEPARATE_FILE/ &redef;
const effective_domain_pattern: pattern = /DEFINED_IN_SEPARATE_FILE/ &redef;

# These are used to match the depth of domain components desired since
# patterns can't (and probably shouldn't be) compiled dynamically).
const tld_extraction_suffixes: table[count] of pattern = {
	[1] = /\.[^\.]+$/,
	[2] = /\.[^\.]+\.[^\.]+$/,
	[3] = /\.[^\.]+\.[^\.]+\.[^\.]+$/,
	[4] = /\.[^\.]+\.[^\.]+\.[^\.]+\.[^\.]+$/,
	[5] = /\.[^\.]+\.[^\.]+\.[^\.]+\.[^\.]+\.[^\.]+$/,
	[6] = /\.[^\.]+\.[^\.]+\.[^\.]+\.[^\.]+\.[^\.]\.[^\.]+$/,
};

function zone_by_depth(domain: string, depth: count): string
	{
	if ( depth !in tld_extraction_suffixes )
		return domain;
	
	local result = find_last(domain, tld_extraction_suffixes[depth]);
	if ( result == "" )
		return domain;
	return result[1:];
	}

function effective_tld(domain: string): string
	{
	local depth=1;
	if ( effective_tlds_4th_level in domain )
		depth=4;
	else if ( effective_tlds_3rd_level in domain )
		depth=3;
	else if ( effective_tlds_2nd_level in domain )
		depth=2;
	return zone_by_depth(domain, depth);
	}
	
function effective_domain(domain: string): string
	{
	local depth=2;
	if ( effective_tlds_4th_level in domain )
		depth=5;
	else if ( effective_tlds_3rd_level in domain )
		depth=4;
	else if ( effective_tlds_2nd_level in domain )
		depth=3;
	return zone_by_depth(domain, depth);
	}
	
# event zeek_init()
# 	{
# 	local domains = vector("blah.www.google.com", "www.google.co.uk", "www.easa.eu.int");
# 	for ( i in domains )
# 		{
# 		print fmt("Original: %s", domains[i]);
# 		print fmt("    Effective TLD: %s", DomainTLD::effective_tld(domains[i]));
# 		print fmt("    Effective domain: %s", DomainTLD::effective_domain(domains[i]));
# 		}
# 	}
