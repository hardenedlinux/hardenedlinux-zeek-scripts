@load base/protocols/http
@load base/protocols/ftp
@load base/protocols/socks

redef HTTP::default_capture_password = T;
redef FTP::default_capture_password = T;
redef SOCKS::default_capture_password = T;
