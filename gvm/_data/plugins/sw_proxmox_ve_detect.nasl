###############################################################################
# OpenVAS Vulnerability Test
#
# Proxmox Virtual Environment Detection
#
# Authors:
# Christian Fischer <info@schutzwerk.com>
#
# Copyright:
# Copyright (C) 2016 SCHUTZWERK GmbH, https://www.schutzwerk.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.111090");
  script_version("2020-08-24T15:18:35+0000");
  script_tag(name:"last_modification", value:"2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2016-03-17 10:42:39 +0100 (Thu, 17 Mar 2016)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Proxmox Virtual Environment Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 SCHUTZWERK GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 3128, 8006);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://pve.proxmox.com");

  script_tag(name:"summary", value:"The script sends a HTTP request to the server and
  attempts to identify a Proxmox Virtual Environment from the reply.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("host_details.inc");
include("cpe.inc");

port = http_get_port( default:8006 );
banner = http_get_remote_headers( port:port );
res = http_get_cache( item:"/", port:port );

if( "erver: pve-api-daemon" >< banner || "Proxmox Virtual Environment</title>" >< res ||
    "/pve2/css/ext-pve.css" >< res || "/pve2/css/ext6-pve.css" >< res || ( "PVE.UserName" >< res && "PVE.CSRFPreventionToken" >< res ) ) {

  version = "unknown";
  install = "/";
  set_kb_item( name:"ProxmoxVE/installed", value:TRUE );

  # e.g. "boxheadline">Proxmox Virtual Environment 1.9</a>
  # nb: only available in quite old versions of Proxmox VE
  ver = eregmatch( pattern:'"boxheadline">Proxmox Virtual Environment ([0-9.]+)</a>', string:res );
  if( ver[1] ) version = ver[1];

  if( version == "unknown" ) {
    # e.g. <link rel="stylesheet" type="text/css" href="/pve2/css/ext6-pve.css?ver=5.1-42" />
    # or <script type="text/javascript" src="/pve2/js/pvemanagerlib.js?ver=5.1-42"></script>
    ver = eregmatch( pattern:'"/pve2/(css/ext6-pve\\.css|js/pvemanagerlib\\.js)\\?ver=([0-9.\\-]+)"', string:res );
    if( ver[2] ) version = ver[2];
  }

  if( version == "unknown" ) {
    # Only the major version but still better then nothing...
    # At this point (if the css/js above failed) a full version is only available via an authenticated API and would return something like 5.0-34
    url = "/pve-docs/pve-admin-guide.html";
    req = http_get( item:url, port:port );
    res = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

    # e.g. <span id="revnumber">version 5.0,</span>
    ver = eregmatch( pattern:">version ([0-9.]+)", string:res );
    if( ver[1] ) {
      version  = ver[1];
      conclUrl = http_report_vuln_url( port:port, url:url, url_only:TRUE );
    }
  }

  # CPE not registered yet
  cpe = build_cpe( value:version, exp:"([0-9.\-]+)", base:"cpe:/a:proxmox:ve:" );
  if( isnull( cpe ) )
      cpe = "cpe:/a:proxmox:ve";

  register_product( cpe:cpe, location:install, port:port, service:"www" );

  log_message( data:build_detection_report( app:"Proxmox Virtual Environment",
                                                 version:version,
                                                 install:install,
                                                 concluded:ver[0],
                                                 concludedUrl:conclUrl,
                                                 cpe:cpe ),
                                                 port:port );
}

exit( 0 );
