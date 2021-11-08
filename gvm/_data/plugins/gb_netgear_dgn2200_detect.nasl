###############################################################################
# OpenVAS Vulnerability Test
#
# NETGEAR DGN2200 Routers Detection
#
# Authors:
# Tameem Eissa <tameem.eissa@greenbone.net>
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107228");
  script_version("2020-08-24T15:18:35+0000");
  script_tag(name:"last_modification", value:"2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2017-06-28 14:43:29 +0200 (Wed, 28 Jun 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("NETGEAR DGN2200 Router Detection (HTTP)");

  script_tag(name:"summary", value:"Detection of NETGEAR DGN2200 Routers.

  The script sends a connection request to the server and attempts to detect the presence of the NETGEAR DGN2200 Router.");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_get_http_banner.nasl");
  script_mandatory_keys("DGN2200/banner");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default: 8080);

res = http_get_cache(port: port, item: "/");

if ('WWW-Authenticate: Basic realm="NETGEAR DGN2200' >< res) {
  set_kb_item(name: "netgear_dgn2200/detected", value: TRUE);
  set_kb_item(name: "netgear/router/detected", value: TRUE);

  version = 'unknown';

  # keeping this in, although the version can only be obtained via authentication right now.
  ver = eregmatch(pattern: 'NETGEAR DGN2200v([0-9])', string: res);
  if (!isnull(ver[1])) {
    version = ver[1];
    set_kb_item(name: "netgear_/version", value: version);
  }

  cpe = build_cpe(value: version, exp: "^([0-9]+)", base: "cpe:/h:netgear:dgn2200:");
  if (!cpe)
    cpe = "cpe:/h:netgear:dgn2200";

  register_product(cpe: cpe, location: "/", port: port, service: "www");

  log_message(data: build_detection_report(app: "NETGEAR DGN2200 Router",
                                           version: version,
                                           install: "/",
                                           cpe: cpe,
                                           concluded: ver[0]),
              port: port);
}

exit( 0 );
