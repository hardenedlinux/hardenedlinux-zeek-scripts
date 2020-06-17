# Normal users don't need to run this script because this module ships with
# the output pregenerated.
#
# If you do decide to run it, it takes the content of this file on stdin:
#    http://mxr.mozilla.org/mozilla-central/source/netwerk/dns/effective_tld_names.dat?raw=1
# This data is now also hosted here:
#    https://publicsuffix.org/list/
#
# The tld-data.bro script is written out on stdout.

puts "module DomainTLD;"
#zone1 = "redef effective_tlds_1st_level +=\n    /\\.("
zone2 = "redef effective_tlds_2nd_level +=\n    /\\.("
zone3 = "redef effective_tlds_3rd_level +=\n    /\\.("
#effective_tlds    = "redef Domain::effective_tld_pattern +=\n    /\\.("
#effective_domains = "redef Domain::effective_domain_pattern +=\n    /\\.[^\\.]+\\.("

STDIN.each_line do |line|
  break if line =~ /===END ICANN DOMAINS===/
  
  if line =~ /^\/\/ xn--/
    line.gsub!(/^\/\/ (xn--[^ ]+).*/, "\\1")
  end
  
  next if line =~ /^$|^\/\/|^!/
  next if line =~ /[\x80-\xff]/
  line.strip!
  line.gsub!(/\./, "\\.")
  
  if line =~ /\..*\..*$/
    zone3 += line.chomp + "|"
  elsif line =~ /\..*$/
    zone2 += line.chomp + "|"
  #elsif line =~ /^[^\.]+$/
  #  zone1 += line.chomp + "|"
  end
  
  #effective_tlds += line.chomp + "|"
  #effective_domains += line.chomp + "|"
end

#zone1 = zone1.chop.chop.chop + ")$/;"
zone2 = zone2.chop.chop.chop + ")$/;"
zone3 = zone3.chop.chop.chop + ")$/;"

#puts zone1.gsub(/\*/, "[^\\.]+")
#puts
puts zone2.gsub(/\*/, "[^\\.]+")
puts
puts zone3.gsub(/\*/, "[^\\.]+")
#puts
#puts effective_tlds.chop.gsub(/\*/, "[^\\.]+") + ")$/;"
#puts
#puts effective_domains.chop.gsub(/\*/, "[^\\.]+") + ")$/;"
