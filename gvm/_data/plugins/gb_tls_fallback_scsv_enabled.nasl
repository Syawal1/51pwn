###############################################################################
# OpenVAS Vulnerability Test
#
# SSL/TLS: TLS_FALLBACK_SCSV Detection
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105483");
  script_version("2020-11-12T09:36:23+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2020-11-12 09:36:23 +0000 (Thu, 12 Nov 2020)");
  script_tag(name:"creation_date", value:"2015-12-11 15:21:49 +0100 (Fri, 11 Dec 2015)");
  script_name("SSL/TLS: TLS_FALLBACK_SCSV Detection");
  script_category(ACT_GATHER_INFO);
  script_family("SSL and TLS");
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_dependencies("gb_tls_version_get.nasl");
  script_mandatory_keys("ssl_tls/port");

  script_tag(name:"summary", value:"This script reports if TLS_FALLBACK_SCSV is enabled or not.");

  script_tag(name:"qod_type", value:"remote_active");

  exit(0);
}

include("mysql.inc"); # For recv_mysql_server_handshake() in open_ssl_socket()
include("ssl_funcs.inc");
include("misc_func.inc");
include("list_array_func.inc");
include("byte_func.inc");

function _check_tls_fallback_scsv( ssl_port, ssl_ver  ) {

  local_var hello, soc, hdr, len, pay, len1, next, mult, hello_done, ssl_port, ssl_ver;

  hello = ssl_hello( version:ssl_ver, add_tls_fallback_scsv:TRUE );

  soc = open_ssl_socket( port:ssl_port );
  if( ! soc )
    return FALSE;

  send( socket:soc, data:hello );

  while ( ! hello_done ) {

    hdr = recv( socket:soc, length:5, timeout:5 );

    if( ! hdr || strlen( hdr ) != 5 ) {
      close( soc );
      return FALSE;
    }

    len = getword( blob:hdr, pos:3 );
    pay = recv( socket:soc, length:len, timeout:5 );

    if( ! pay ) {
      close( soc );
      return FALSE;
    }

    if( ord( hdr[0] ) == SSLv3_ALERT ) {
      if( strlen( pay ) < 2 ) {
        close( soc );
        return FALSE;
      }

      # If TLS_FALLBACK_SCSV appears in ClientHello.cipher_suites and the
      # highest protocol version supported by the server is higher than
      # the version indicated in ClientHello.client_version, the server
      # MUST respond with an inappropriate_fallback alert.
      if( ord( pay[ 1 ] ) == SSLv3_ALERT_INAPPROPRIATE_FALLBACK ) {
        close( soc );
        return TRUE;
      }
    }

    if( ord( pay[0] ) == 13 && ord( hdr[0] ) == 22 ) {
      len1 = getword( blob:pay, pos:2 );
      next = substr( pay, len1 + 4 );

      if( next && ord( next[0] ) == 14 ) {
        hello_done = TRUE;
        close( soc );
        return FALSE;
      }
    }

    if( ( strlen( pay ) - 4 ) > 0 )
      mult = substr( pay, ( strlen( pay ) - 4 ), strlen( pay ) );

    if( ( ord( pay[0] ) == 14 || ( mult && ord( mult[0] ) == 14 ) ) && ord( hdr[0] ) == 22 ) {
      hello_done = TRUE;
      close( soc );
      return FALSE;
    }
  }

  close( soc );
  return FALSE;
}

if( ! port = tls_ssl_get_port() )
  exit( 0 );

# TODO: Also check TLS_FALLBACK_SCSV for all other protocols
ssl_ver = SSL_v3;

if( _check_tls_fallback_scsv( ssl_port:port, ssl_ver:ssl_ver ) ) {
  report = 'It was determined that the remote TLSv1.0+ service supports the TLS_FALLBACK_SCSV and is therefore not affected by downgrading attacks like the POODLE vulnerability.';
  set_kb_item( name:"tls_fallback_scsv_supported/" + port, value:TRUE );
  #log_message( port:port, data:report );
  exit( 99 );
}

report = 'It was determined that the remote TLSv1.0+ service does not support the TLS_FALLBACK_SCSV and might be affected by downgrading attacks like the POODLE vulnerability.';
#log_message( port:port, data:report );
exit( 0 );
