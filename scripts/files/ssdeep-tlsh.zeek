export {
redef record Files::Info += {
  ## Logging stream for file analysis.
  ssdeep: string &log &optional;
  tlsh: string &log &optional;
  };
}

event file_sniff(f: fa_file, meta: fa_metadata)
  {

  Files::add_analyzer(f, Files::ANALYZER_SSDEEP);
  Files::add_analyzer(f, Files::ANALYZER_TLSH);

  }

event  file_fuzzy_hash(f: fa_file, kind: string, hash: string)
  {
  if(kind == "ssdeep")
    f$info$ssdeep = hash;
    else
      f$info$tlsh = hash;
      }