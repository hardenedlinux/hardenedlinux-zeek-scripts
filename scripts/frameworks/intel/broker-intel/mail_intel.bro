
@load base/frameworks/broker
@load @load packages/vast
global email_vast: event(msg: string, vast_output: int);

event Broker::peer_added(endpoint: Broker::EndpointInfo, msg: string) {
  if ( ! endpoint?$network )
      return;
      local net = endpoint$network;
	print "vast connect successful", endpoint;
	print "will send some greetings";

	local i = output;
	while (list_num == 0) {

		## creating this event will auto publish it (see the zeek_init event)
		event email_vast("Log output %s", email_data);
	}


event zeek_init()
  {
  Broker::subscribe(mail_topic);
  Broker::peer(bridge_host, bridge_port);
  }
