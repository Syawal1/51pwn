###############################################################################
# OpenVAS Vulnerability Test
#
# SSL/TLS: HTTP Public Key Pinning (HPKP) Detection
#
# Authors:
# Christian Fischer <christian.fischer@greenbone.net>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108245");
  script_version("2020-08-28T07:42:46+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2020-08-28 07:42:46 +0000 (Fri, 28 Aug 2020)");
  script_tag(name:"creation_date", value:"2017-10-09 08:07:41 +0200 (Mon, 09 Oct 2017)");
  script_name("SSL/TLS: HTTP Public Key Pinning (HPKP) Detection");
  script_category(ACT_GATHER_INFO);
  script_family("SSL and TLS");
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  # nb: Don't add a dependency to e.g. webmirror.nasl or DDI_Directory_Scanner.nasl
  # to allow a minimal SSL/TLS check configuration.
  script_dependencies("find_service.nasl", "httpver.nasl", "gb_tls_version_get.nasl");
  script_require_ports("Services/www", 443);
  script_mandatory_keys("ssl_tls/port");

  script_xref(name:"URL", value:"https://owasp.org/www-project-secure-headers/");
  script_xref(name:"URL", value:"https://owasp.org/www-project-secure-headers/#public-key-pinning-extension-for-http-hpkp");
  script_xref(name:"URL", value:"https://tools.ietf.org/html/rfc7469");
  script_xref(name:"URL", value:"https://securityheaders.io/");

  script_tag(name:"summary", value:"This script checks if the remote HTTPS server has HPKP enabled.

  Note: Most major browsers have dropped / deprecated support for this header in 2020.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");

port = http_get_port( default:443, ignore_cgi_disabled:TRUE );
if( get_port_transport( port ) < ENCAPS_SSLv23 )
  exit( 0 );

banner = http_get_remote_headers( port:port );
# We should not expect a HPKP header without a 20x or 30x status code in the response
# e.g. nginx -> https://nginx.org/en/docs/http/ngx_http_headers_module.html#add_header
# 200, 201 (1.3.10), 204, 206, 301, 302, 303, 304, 307 (1.1.16, 1.0.13), or 308 (1.13.0).
#
# 304 has a special meaning and shouldn't contain any additional headers -> https://tools.ietf.org/html/rfc2616#section-10.3.5
# E.g. mod_headers from Apache won't add additional Headers on this code so don't check it here
if( ! banner || banner !~ "^HTTP/1\.[01] (20[0146]|30[12378])" )
  exit( 0 );

if( ! pkp = egrep( pattern:"^Public-Key-Pins\s*:", string:banner, icase:TRUE ) ) { # Public-Key-Pins-Report-Only is used for testing only
  set_kb_item( name:"hpkp/missing", value:TRUE );
  set_kb_item( name:"hpkp/missing/port", value:port );
  exit( 0 );
}

# max-age is required: https://tools.ietf.org/html/rfc7469#page-19
# Assume a missing HPKP if its not specified
if( "max-age=" >!< tolower( pkp ) ) {
  set_kb_item( name:"hpkp/missing", value:TRUE );
  set_kb_item( name:"hpkp/missing/port", value:port );
  set_kb_item( name:"hpkp/max_age/missing/" + port, value:TRUE );
  set_kb_item( name:"hpkp/" + port + "/banner", value:pkp );
  exit( 0 );
}

# Assuming missing support if value is set to zero
if( "max-age=0" >< tolower( pkp ) ) {
  set_kb_item( name:"hpkp/missing", value:TRUE );
  set_kb_item( name:"hpkp/missing/port", value:port );
  set_kb_item( name:"hpkp/max_age/zero/" + port, value:TRUE );
  set_kb_item( name:"hpkp/" + port + "/banner", value:pkp );
  exit( 0 );
}

# Assuming missing support if no pin-sha256= is included
# Currently only pin-sha256 is supported / defined but this might change in the future
if( "pin-sha256=" >!< tolower( pkp ) ) {
  set_kb_item( name:"hpkp/missing", value:TRUE );
  set_kb_item( name:"hpkp/missing/port", value:port );
  set_kb_item( name:"hpkp/pin/missing/" + port, value:TRUE );
  set_kb_item( name:"hpkp/" + port + "/banner", value:pkp );
  exit( 0 );
}

set_kb_item( name:"hpkp/available", value:TRUE );
set_kb_item( name:"hpkp/available/port", value:port );
set_kb_item( name:"hpkp/" + port + "/banner", value:pkp );

if( "includesubdomains" >!< tolower( pkp ) ) {
  set_kb_item( name:"hpkp/includeSubDomains/missing", value:TRUE );
  set_kb_item( name:"hpkp/includeSubDomains/missing/port", value:port );
}

ma = eregmatch( pattern:'max-age=([0-9]+)', string:pkp, icase:TRUE );

if( ! isnull( ma[1] ) )
  set_kb_item( name:"hpkp/max_age/" + port, value:ma[1] );

log_message( port:port, data:'The remote HTTPS server is sending the "HTTP Public Key Pinning" header.\n\nHPKP-Header:\n\n' + pkp );
exit( 0 );