###############################################################################
# OpenVAS Vulnerability Test
#
# Outlook Web App Detection
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.105150");
  script_version("2020-10-19T14:11:39+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2020-10-19 14:11:39 +0000 (Mon, 19 Oct 2020)");
  script_tag(name:"creation_date", value:"2014-12-22 14:13:35 +0100 (Mon, 22 Dec 2014)");
  script_name("Microsoft Exchange Outlook Web App (OWA) Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "httpver.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of the Microsoft Exchange Outlook Web App (OWA)
  and the Microsoft Exchange Server running this Web App.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("host_details.inc");

port = http_get_port( default:443 );
if( ! http_can_host_asp( port:port ) )
  exit( 0 );

url = "/owa/auth/logon.aspx";
buf = http_get_cache( item:url, port:port );

if( "Microsoft Corporation.  All rights reserved" >< buf && ( "<title>Outlook Web App" >< buf || "X-OWA-Version:" >< buf ) ) {

  set_kb_item( name:"ms/owa/installed", value:TRUE );

  vers = "unknown";
  conclurl = http_report_vuln_url( port:port, url:url, url_only:TRUE );

  version = eregmatch( pattern:"X-OWA-Version: ([0-9.]+)", string:buf );
  if( isnull( version[1] ) )
    version = eregmatch( pattern:"/owa/([0-9.]+)/themes/", string:buf );

  if( isnull( version[1] ) )
    version = eregmatch( pattern:"/owa/auth/([0-9.]+)/themes/", string:buf );

  if( ! isnull( version[1] ) )
    vers = version[1];

  owa_cpe = "cpe:/a:microsoft:outlook_web_app";
  exc_cpe = "cpe:/a:microsoft:exchange_server";
  if( vers && vers != "unknown" ) {
    owa_cpe += ":" + vers;
    exc_cpe += ":" + vers;
  }

  register_and_report_os( os:"Microsoft Windows", cpe:"cpe:/o:microsoft:windows", desc:"Microsoft Exchange Outlook Web App (OWA) Detection (HTTP)", runs_key:"windows" );

  register_product( cpe:owa_cpe, location:url, port:port, service:"www" );
  register_product( cpe:exc_cpe, location:"/", port:port, service:"www" );

  report = build_detection_report( app:"Microsoft Exchange Outlook Web App (OWA)",
                                   version:vers,
                                   install:url,
                                   cpe:owa_cpe,
                                   concludedUrl:conclurl,
                                   concluded:version[0] );
  report += '\n\n';
  report += build_detection_report( app:"Microsoft Exchange Server",
                                    version:vers,
                                    install:"/",
                                    cpe:exc_cpe,
                                    concludedUrl:conclurl,
                                    concluded:version[0] );

  log_message( port:port, data:report );
}

exit( 0 );
