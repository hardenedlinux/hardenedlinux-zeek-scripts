#!/usr/bin/env python
# [[https://github.com/laramies/theHarvester][laramies/theHarvester: E-mails, subdomains and names Harvester - OSINT]]
# [[https://github.com/m4ll0k/Infoga][m4ll0k/Infoga: Infoga - Email OSINT]]
#
# Harverster recived email to intell from Zeek Logs, the result will be stored in email_intel
redef exit_only_after_terminate = T;

global email_vast: event(msg: string, i: int);

event Broker::peer_added(endpoint: Broker::EndpointInfo, msg: string) {
	print "peering successful", endpoint;
	print "will send some greetings";

	local i = 0;
	while (i < 10) {

		## creating this event will auto publish it (see the zeek_init event)
		event greet("hi there", ++i);
	}
