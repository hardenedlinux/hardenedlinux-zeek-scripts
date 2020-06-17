module HTTP;
export {
 redef enum Notice::Type += {
 ## Generated if a Command injection takes place using URL
     URI_Injection,
     Basic_Auth_Server
};
}
event http_header(c: connection, is_orig: bool, name: string, value: string)
 {

 if (/AUTHORIZATION/ in name && /Basic/ in value)
 {

 local parts = split_string1(decode_base64(sub_bytes(value, 7, |value|)), /:/);

 NOTICE([$note=HTTP::Basic_Auth_Server,
 $msg=fmt("username: %s password: %s", parts[1],
 HTTP::default_capture_password == F ? "Blocked" : parts[2]),
 $conn=c
 ]);
 }
 }
