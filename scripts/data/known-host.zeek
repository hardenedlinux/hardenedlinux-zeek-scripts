module PublicData;
export{
    const internal_host: table[addr] of string = {
		[10.170.120.112] = "nixos",
	};

    const vulnerable_host_port: table[addr] of table[port] of string = {
        [10.1.1.1] = table([530/udp] = "printer1/udp"), 
        [10.1.1.2] = table([139/tcp] = "printer2/tcp"),
    };
}