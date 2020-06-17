# Version 1.0 (May 2019)
#
# Authors: Zer0d0y@天御实验室 (Zer0d0y@tianyulab.com)
#
# Copyright (c) 2019, 天御[攻防]实验室.
# All rights reserved.
# Licensed under the BSD 3-Clause license. 
#
# 支持Zeek Version v2.6.x
# Modified by hardenedlinux <2019-09-09 Mon>
@load base/frameworks/notice
@load frameworks/files/hash-all-files
@load ./virustotal.zeek
@load ./known_hash.zeek
module VirusTotal;

export {
    redef enum Notice::Type += {
        Match
    };

    ## Number of positive AV hits to do the Match notice.
    const hits_to_notice = 10 &redef;

    ## We want to check virustotal for files of the following types.
    const match_file_types = /application\/x-dosexec/ |
                             /application\/x-executable/ &redef;
}

event file_hash(f: fa_file, kind: string, hash: string)
    {
    
    if ( kind == "sha1" && f$info?$mime_type &&
         match_file_types in f$info$mime_type )
        {
        if (hash !in Known::hashes)
            {
            when ( local info = VirusTotal::scan_hash(f, hash) )
            {
            if ( |info$hits| < hits_to_notice )
                break;
            local downloader: addr = 0.0.0.0;
            for ( host in f$info$rx_hosts )
                {
                # Pick a receiver host to use here (typically only one anyway)
                downloader = host;
                }

            NOTICE([$note=VirusTotal::Match,
                $msg = fmt("VirusTotal match on %d AV engines hit by %s", |info$hits|, downloader),
                $sub = info$permalink,
                $n   = |info$hits|,
                $src = downloader]);
                }
        }
    }
}
