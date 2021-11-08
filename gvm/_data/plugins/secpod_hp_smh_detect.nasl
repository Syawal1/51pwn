###############################################################################
# OpenVAS Vulnerability Test
#
# HP System Management Homepage (SMH) Version Detection
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2009 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.900657");
  script_version("2020-08-24T15:18:35+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2009-06-01 09:35:57 +0200 (Mon, 01 Jun 2009)");
  script_name("HP System Management Homepage (SMH) Version Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 2301, 2381);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Detection of HP System Management Homepage (SMH).

  The script sends a request to get the banner and attempts to extract the
  version number from the reply.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("cpe.inc");

port = http_get_port( default:2301 );
req = http_get(port: port, item: "/cpqlogin.htm");
res = http_keepalive_send_recv(port: port, data: req);

if ("<title>HP System Management Homepage" >< res && "smhcopyright" >< res) {
  version = "unknown";

  vers = eregmatch(pattern: 'smhversion = "HP System Management Homepage v([0-9.]+)', string: res);
  if (!isnull(vers[1])) {
    version = vers[1];
    set_kb_item(name: "HP/SMH/version", value: version);
  }

  set_kb_item(name: "HP/SMH/installed", value: TRUE);

  cpe = build_cpe(value: version, exp: "^([0-9.]+)", base:"cpe:/a:hp:system_management_homepage:");
  if (!cpe)
    cpe = 'cpe:/a:hp:system_management_homepage';

  register_product(cpe: cpe, location: "/", port: port, service: "www");

  log_message(data: build_detection_report(app: "HP System Management Homepage (SMH)",
                                           version: version,
                                           install: "/",
                                           cpe: cpe,
                                           concluded: vers[0]),
              port: port);
  exit(0);
}

exit(0);
