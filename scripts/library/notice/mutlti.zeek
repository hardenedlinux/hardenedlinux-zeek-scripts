# Simple notice correlation for notices and Intel (see hook below)

@load base/frameworks/intel
@load base/frameworks/notice
@load policy/frameworks/intel/do_notice.bro
@load policy/protocols/ssl/validate-certs.bro

module Multi;

export {
  redef enum Notice::Type += {
    Multi::Multi_Notice,
  Multi::Multi_Notice_AutoBlock,
  Multi::Multi_Notice_AutoBlockAlarm,
  Multi::Single_Notice_Threshold,
  Multi::Single_Notice_Threshold_Block
};

global multi_notice_types: set[Notice::Type] = {
        SSH::Password_Guessing,
#  		Bash::HTTP_Header_Attack
        SSL::Invalid_Server_Cert,
        CVE_2017_12240::LARGE_DHCP_PACKET
} &redef;

global multi_non_block_thres: count = 3 &redef;

global multi_notice_non_block_types: set[Notice::Type] = {
#  	 	Test::HTTP_Header_Alert_with_src
} &redef;

global watch_hosts: table[addr] of table[Notice::Type] of count &write_expire = 120 min;
global watch_host: function(whost: addr, n: Notice::Info);

# single notice threshold
type SNT: record {
  thres: count;
  block: bool;
  blockthres: count;
  };

# test w/ Intel even though we'll most likely use SenstiveURI, etc.  
global single_notice_threshold: table[Notice::Type] of SNT = {

} &redef;

}

redef Notice::alarmed_types += {
	Multi::Multi_Notice,
Multi::Multi_Notice_AutoBlock,
Multi::Multi_Notice_AutoBlockAlarm
};

function watch_host(whost: addr, n: Notice::Info){
	local wn: Notice::Info;
	local notice_string: string = "";
	local notice_string_sub: string = "";
	local multi_note: Notice::Type = Multi::Multi_Notice_AutoBlock;
	local num_notices: count;


	if (whost !in watch_hosts){
		local init_wh: table[Notice::Type] of count = {[n$note] = 1};
		watch_hosts[whost] = init_wh;
	  }else if(n$note !in watch_hosts[whost]){
	watch_hosts[whost][n$note] = 1;
	}else{
++watch_hosts[whost][n$note];

# loop through SNT data here
if(n$note in single_notice_threshold){
	if(watch_hosts[whost][n$note] == single_notice_threshold[n$note]$thres){
    NOTICE([$note=Multi::Single_Notice_Threshold,
  $msg=fmt("Crossed threshold of %d for %s",
	single_notice_threshold[n$note]$thres,n$note),
  $src=whost,
  $identifier=cat(whost)]);
}else if(single_notice_threshold[n$note]$block == T && watch_hosts[whost][n$note] == single_notice_threshold[n$note]$blockthres){
NOTICE([$note=Multi::Single_Notice_Threshold_Block,
$msg=fmt("Crossed block threshold of %d for %s",
single_notice_threshold[n$note]$blockthres,n$note),
$src=whost,
$identifier=cat(whost)]);
}
}

}

num_notices = |watch_hosts[whost]|;
if(num_notices >= 1){

	for (wnote in watch_hosts[whost]){
		notice_string = cat(notice_string,wnote,"_");
		if(|notice_string_sub| > 0){
			notice_string_sub=cat(notice_string_sub,"__");
			}
		notice_string_sub=cat(notice_string_sub,wnote,":",watch_hosts[whost][wnote]);
		}

	if(num_notices >= multi_non_block_thres){
		multi_note = Multi::Multi_Notice_AutoBlockAlarm;
		}else if((wnote in multi_notice_non_block_types) && (num_notices < multi_non_block_thres)){
	multi_note = Multi::Multi_Notice;
	}

wn = Notice::Info($note=multi_note,
	$msg="Host triggered multi-notice correlation",
	$sub=notice_string_sub,
	$src=whost,
  $identifier=cat(whost,notice_string));

# will only pass the $conn info if the last notice that triggered Multi had the a $conn
# Future:  need to keep track of $conn (or samples) for the whole watchhost record,
# but even that is a little misleading.
if ( n?$conn ){
  wn$conn = n$conn;
  }
NOTICE(wn);

} 


}

hook Notice::policy(n: Notice::Info)
{

if( n$note in multi_notice_types ){
	if(n?$conn){
		watch_host(n$conn$id$orig_h,n);
		}else{
	watch_host(n$src,n);
	}
}
}

event Intel::log_intel(rec: Intel::Info){

  # any Intel hit, add to watch list.
  local wn = Notice::Info($note=Intel::Notice);
  watch_host(rec$id$orig_h,wn);
  }
