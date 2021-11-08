###############################################################################
# OpenVAS Vulnerability Test
#
# Support methods for DNS
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

# @brief Make various queries to the CHAOS TXT record and save the reply string in the KB for further analysis
#
# @param soc   Socket to run the query at
# @param proto Protocol to use ("tcp" or "udp")
# @param port  Port the socket is bound to
#
# @return The reply from the server as a string if there was no error, otherwise NULL.
#
function dnsVersionReq( soc, proto, port ) {

  local_var soc, proto, port;
  local_var raw_data_init, queries, query_list, _query, _query_str, len, raw_data, offset, result, base, size, slen, whole_data, i;

  if( ! soc ) {
    set_kb_item( name:"nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#soc#-#dnsVersionReq" );
    return NULL;
  }

  if( ! proto ) set_kb_item( name:"nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#proto#-#dnsVersionReq" );

  if( ! port ) set_kb_item( name:"nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#port#-#dnsVersionReq" );

  raw_data_init = raw_string( 0x00, 0x0A, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07 );

  queries = make_list( "version",
                       "version.pdns",
                       "version.bind",
                       "version.server",
                       "erre-con-erre-cigarro.maradns.org",
                       "version.maradns", # Both found in https://maradns.samiam.org/tutorial/update.html
                       "version.mydns" ); # Found in https://github.com/dwighthubbard/mydns-dhubbard/blob/c8e4c1bb9834408b04ac8142628becef345496f5/src/mydns/status.c#L75

  query_list = make_list();

  # Try both lowercase and uppercase
  foreach _query( queries )
    query_list = make_list( query_list, _query, toupper( _query ) );

  foreach _query_str( query_list ) {

    if( proto == "tcp" ) {
      len = strlen( _query_str ) + 18;
      raw_data = raw_string( 0x00, len ) + raw_data_init;
      offset = 2;
    } else {
      offset = 0;
      raw_data = raw_data_init;
    }

    _query_str = str_replace( string:_query_str, find:".", replace:raw_string( 0x04 ) );
    raw_data = raw_data + _query_str;
    raw_data = raw_data + raw_string( 0x00, 0x00, 0x10, 0x00, 0x03 );

    send( socket:soc, data:raw_data );
    result = recv( socket:soc, length:1000 );

    if( result ) {
      if( ( ( result[0+offset] == raw_string( 0x00 ) ) || ( result[0+offset] == raw_string( 0xA5 ) ) ) &&
          ( ( result[1+offset] == raw_string( 0x0A ) ) || ( result[1+offset] == raw_string( 0x12 ) ) ) ) {

        if( ( ( result[2+offset] == raw_string( 0x81 ) ) || ( result[2+offset] == raw_string( 0x84 ) ) ||
            ( result[2+offset] == raw_string( 0x85 ) ) ) &&
            ( ( result[3+offset] == raw_string( 0x80 ) ) || ( result[3+offset] == raw_string( 0x00 ) ) ) ) {

          if( ( result[4+offset] == raw_string( 0x00 ) ) && ( result[5+offset] == raw_string( 0x01 ) ) ) {

            if( ( result[6+offset] == raw_string( 0x00 ) ) && ( result[7+offset] == raw_string( 0x01 ) ) ) {

              if( result[18+strlen(_query_str)+offset] >= 0xc0 ) {
                base = 28 + strlen( _query_str );
              } else {
                base = 40 + strlen( _query_str );
              }

              size = ord( result[base+1+offset] );
              slen = base + 3 + offset - 1;
              if( slen > strlen( result ) )
                return;

              if( size > 0 ) {
                whole_data = "";
                for( i = 0; i < size-1; i++ )
                  whole_data = whole_data + result[base+3+i+offset];

                set_kb_item( name:"DNS/" + proto + "/version_request", value:port );
                set_kb_item( name:"DNS/" + proto + "/version_request/" + port, value:whole_data );
                return whole_data;
              }
            }
          }
        }
      }
    }
  }
}
