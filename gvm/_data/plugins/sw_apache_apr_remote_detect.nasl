##############################################################################
# OpenVAS Vulnerability Test
#
# Apache APR Version Detection (Remote)
#
# Authors:
# Christian Fischer <info@schutzwerk.com>
#
# Copyright:
# Copyright (c) 2016 SCHUTZWERK GmbH, http://www.schutzwerk.com
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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
  script_oid("1.3.6.1.4.1.25623.1.0.111098");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2020-08-24T15:18:35+0000");
  script_tag(name:"last_modification", value:"2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2016-05-01 15:35:19 +0200 (Sun, 01 May 2016)");
  script_name("Apache APR Version Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 SCHUTZWERK GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "secpod_apache_detect.nasl", "global_settings.nasl");
  script_require_keys("apache/installed");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"This script tries to detects the installed version of Apache APR
  from an exposed /server-info status page.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("cpe.inc");
include("host_details.inc");

port = http_get_port( default:80 );

url = "/server-info";

buf = http_get_cache( item:url, port:port );

aprVer = eregmatch( pattern:'Server loaded APR Version:([ /<>a-zA-Z0-9+="]+)<tt>([^<]+)</tt>', string:buf );

if( ! isnull( aprVer[2] ) ) {

  set_kb_item( name:"Apache/APR/Ver", value:aprVer[2] );

  cpe = build_cpe( value:aprVer[2], exp:"^([0-9.]+)", base:"cpe:/a:apache:portable_runtime:" );
  if( ! cpe )
    cpe = "cpe:/a:apache:portable_runtime";

  register_product( cpe:cpe, location:port + "/tcp", port:port, service:"www" );

  log_message( data:build_detection_report( app:"Apache APR",
                                            version:aprVer[2],
                                            install:port + "/tcp",
                                            cpe:cpe,
                                            concluded:aprVer[0] ),
                                            port:port );
}

apuVer = eregmatch( pattern:'Server loaded APU Version:([ /<>a-zA-Z0-9+="]+)<tt>([^<]+)</tt>', string:buf );

if( ! isnull( apuVer[2] ) ) {

  set_kb_item( name:"Apache/APR-Utils/Ver", value:apuVer[2] );

  cpe = build_cpe( value:apuVer[2], exp:"^([0-9.]+)", base:"cpe:/a:apache:apr-util:" );
  if( ! cpe )
    cpe = "cpe:/a:apache:apr-util";

  register_product( cpe:cpe, location:port + "/tcp", port:port, service:"www" );

  log_message( data:build_detection_report( app:"Apache APR-Utils",
                                            version:apuVer[2],
                                            install:port + "/tcp",
                                            cpe:cpe,
                                            concluded:apuVer[0] ),
                                            port:port );
}

exit( 0 );
