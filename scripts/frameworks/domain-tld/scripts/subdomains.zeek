const subdomains =  
                        /^dns[0-9]*\./     |
                        /^smtp[0-9]*\./    |
                        /^mail[0-9]*\./    |
                        /^pop[0-9]*\./     |
                        /^imap[0-9]*\./    |
                        /^www[0-9]*\./     |
                        /^ftp[0-9]*\./     |
                        /^img[0-9]*\./     |
                        /^images?[0-9]*\./ |
                        /^search[0-9]*\./  |
                    /^nginx[0-9]*\./ &redef;










# TEST CODE		    
# event DNS::log_dns(rec: DNS::Info)
# {
# 	if (! rec?$query)
#         return;
#     local query = rec$query;
#     if ( subdomains in query ){
#         query = sub(query,subdomains,"");
#         query = to_lower(query);
#         local q = DomainTLD::effective_domain(query);
#         print q;
#     }
# }		