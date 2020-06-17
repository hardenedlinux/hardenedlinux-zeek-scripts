@load base/frameworks/files
@load base/frameworks/notice
@load frameworks/files/hash-all-files

# <2019-05-10 Fri> add ssdeep tlsh hash;

module FileAnalytics_DB;

export {
  #
  # NOTE: Order very much matters here. The firt attribute is used as the PK
  # in Sqlite3 the way the Sqlite writer currently works in Bro.
  #
  type Info: record {
    ts:       time    &log;
    uid:      string  &log;
    fuid:     string  &log;
    md5:      string  &log;
    filebuf:  string  &log &optional;
    ssdeep: string &log &optional;
    tlsh: string &log &optional;
  };

  redef enum Log::ID += { LOG };

  # Define a hook event. By convention, this is called
  # "log_<stream>".
  global log_file_analytics_db: event(rec: Info);

  type db_monitor_key: record {
    uid: string;
    ts:	 time;
    md5: string;
    ssdeep: string;
    tlsh: string;
  };

  type db_monitor_contents: record {
    fuid:         string;
    id:           conn_id;
    retry_count:  count;
  };

  ## Define whether or not to extract a filebuf for insertion into the log
  const extract_filebuf = T &redef;
  ## Define the number of bytes to extract from the bof_buffer
  const bytes_to_extract = 50 &redef;

  global db_monitor: table[db_monitor_key] of db_monitor_contents;
}

global analysis_allowed_mime_types: set[string] = {
  "application/x-dosexec",
  "application/x-executable",
  "application/x-msdownload",
  "application/octet-stream",
  "application/x-shockwave-flash",
  "application/pdf",
  "application/x-director",
  "application/vnd.ms-cab-compressed",
  "application/x-java-applet",
  "application/jar",
};

global request_db = "/opt/db/request";

event zeek_init() {
  local filter: Log::Filter = [
    $name="sqlite",
    $path=request_db,
    $config=table(["tablename"] = "request"),
    $writer=Log::WRITER_SQLITE
  ];

  Log::create_stream(FileAnalytics_DB::LOG, [$columns=Info, $ev=log_file_analytics_db]);
  Log::add_filter(FileAnalytics_DB::LOG, filter);
  Log::remove_filter(FileAnalytics_DB::LOG, "default");
}
event file_sniff(f: fa_file, meta: fa_metadata)
    {

  Files::add_analyzer(f, Files::ANALYZER_SSDEEP);
  Files::add_analyzer(f, Files::ANALYZER_TLSH);

  }

event file_state_remove(f: fa_file) {
if(kind == "ssdeep")
    f$info$ssdeep = hash;
    else
      f$info$tlsh = hash;
  if ( f$info?$md5 ) {
  	if ( f$info?$mime_type ) {
  		if ( f$info$mime_type in analysis_allowed_mime_types ) {
        local id: conn_id;
        local uid: string;
        local _filebuf: string = "";

        for ( u in f$info$conn_uids ) {
      	   uid = u;
        }

        if ( extract_filebuf ) {
        	if ( f?$bof_buffer && |f$bof_buffer| >= bytes_to_extract ) {
      		  _filebuf = string_to_ascii_hex(f$bof_buffer[:bytes_to_extract]);
        	}
        }


        local tmp: Info = [ $uid=uid,
                            $ts=f$info$ts,
                            $fuid=f$info$fuid,
                            $md5=f$info$md5,
                            $ssdeep=f$info$ssdeep,
                            $tlsh=f$info$tlsh,
                            $filebuf=_filebuf ];

        Log::write(FileAnalytics_DB::LOG, tmp);

        local t_key: db_monitor_key = [ $uid=uid,
                                        $ts=f$info$ts,
                                        $md5=f$info$md5,
                                        $ssdeep=f$info$ssdeep,
                        				$tlsh=f$info$tlsh];

        if ( t_key !in db_monitor ) {
          db_monitor[t_key] = [$fuid=f$info$fuid,
          $id=id,
          $retry_count=0];
        } else {
          # print fmt("t_key exists already = %s", t_key);
        }
      }
    }
  }
}
