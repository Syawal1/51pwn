###############################################################################
# OpenVAS Vulnerability Test
#
# mod_perl Version Detection
#
# Authors:
# Michael Meyer
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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
  script_oid("1.3.6.1.4.1.25623.1.0.100129");
  script_version("2020-08-24T15:18:35+0000");
  script_tag(name:"last_modification", value:"2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2009-04-13 18:06:40 +0200 (Mon, 13 Apr 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("mod_perl Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_dependencies("gb_get_http_banner.nasl");
  script_mandatory_keys("mod_perl/banner");

  script_tag(name:"summary", value:"Get the version of mod_perl.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");
include("cpe.inc");
include("host_details.inc");

port = http_get_port( default:80 );

if( ! banner = http_get_remote_headers( port:port ) )
  exit( 0 );

if( ! concl = egrep( pattern:"Server\s*:\s*.+mod_perl", string:banner, icase:TRUE ) )
  exit( 0 );

concl = chomp( concl );
install = "/";
version = "unknown";

vers = eregmatch( string:concl, pattern:"Server\s*:\s*.+mod_perl/([0-9.]+)", icase:TRUE );
if( ! isnull( vers[1] ) ) {
  version = vers[1];
  concl = vers[0];
}

set_kb_item( name:"www/" + port + "/mod_perl", value:version );
set_kb_item( name:"mod_perl/detected", value:TRUE );

cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:apache:mod_perl:" );
if( ! cpe )
  cpe = "cpe:/a:apache:mod_perl";

register_product( cpe:cpe, location:install, port:port, service:"www" );
log_message( data:build_detection_report( app:"mod_perl",
                                          version:version,
                                          install:install,
                                          cpe:cpe,
                                          concluded:concl ),
                                          port:port );
exit( 0 );
