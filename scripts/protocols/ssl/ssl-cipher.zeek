# Add list of SSL/TLS cipher suites supported by clients to ssl log file
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#
# The Initial Developer of the Original Code is
# Mozilla Corporation
# Portions created by the Initial Developer are Copyright (C) 2014
# the Initial Developer. All Rights Reserved.
#
# Contributor(s):
# Original code and idea - Johanna Amann, Bro/ICSI - johanna@icir.org
# Random bugs and extensions support - Michal Purzynski mpurzynski@mozilla.com
# adding event ssl_client_hello to Bro 2.6 or later 
@load base/protocols/ssl

module SSL;

export {
	redef record SSL::Info += {
		client_ciphers: set[string] &log &optional &default=string_set();
		client_curves: set[string] &log &optional &default=string_set();
		extensions: set[string] &log &optional &default=string_set();
		point_formats: set[string] &log &optional &default=string_set();
	};
}
event ssl_client_hello(c: connection, version: count, record_version: count,
    possible_ts: time, client_random: string, session_id: string,
    ciphers: index_vec, comp_methods: index_vec)
{
	if ( ! c?$ssl )
		return;
	if ( |ciphers| == 0 )
		return;

	for ( cipher in ciphers ) {
		add c$ssl$client_ciphers[SSL::cipher_desc[ciphers[cipher]]];
	}
}

event ssl_extension(c: connection, is_orig: bool, code: count, val: string)
{
	if ( ! c?$ssl )
		return;

	add c$ssl$extensions[SSL::extensions[code]];
}

event ssl_extension_elliptic_curves(c: connection, is_orig: bool,
    curves: index_vec)
{
	if ( ! c?$ssl )
		return;
	if ( |curves| == 0 )
		return;

	for ( curve in curves ) {
		add c$ssl$client_curves[ec_curves[curves[curve]]];
	}
}

event ssl_extension_ec_point_formats(c: connection, is_orig: bool,
    point_formats: index_vec)
{
	if ( ! c?$ssl )
		return;
	if ( |point_formats| == 0 )
		return;

	for ( point in point_formats ) {
		add c$ssl$point_formats[ec_point_formats[point_formats[point]]];
	}
}
