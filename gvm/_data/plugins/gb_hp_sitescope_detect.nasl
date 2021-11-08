###############################################################################
# OpenVAS Vulnerability Test
#
# HP SiteScope Version Detection
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.805284");
  script_version("2020-08-24T15:18:35+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2015-02-23 10:54:54 +0530 (Mon, 23 Feb 2015)");
  script_name("HP SiteScope Detection (HTTP)");

  script_tag(name:"summary", value:"Detects the installed version of
  HP SiteScope.

  This script sends an HTTP GET request and tries to get the version from the
  response.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_get_http_banner.nasl");
  script_mandatory_keys("SiteScope/banner");
  script_require_ports("Services/www", 8080);
  exit(0);
}

include("cpe.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("host_details.inc");

port = http_get_port(default:8080);
if(!banner = http_get_remote_headers(port:port))
  exit(0);

if(concl = egrep(string:banner, pattern:"(Server: |Location: .*)SiteScope", icase:TRUE)) {

  concl = chomp(concl);
  version = "unknown";
  dir = "/";

  set_kb_item(name:"hp/sitescope/installed", value:TRUE);

  vers = eregmatch(pattern:"Server: SiteScope/([^ ]+)", string:banner);
  if(!isnull(vers[1])){
    version = vers[1];
    concl = vers[0];
  } else {
    req = http_get(item:"/SiteScope/", port:port);
    res = http_keepalive_send_recv(port:port, data:req);

    if(">Login - SiteScope<"  >< res ||
       "HostedSiteScopeMessage.jsp?messageSeverity=" >< res) {
      dir = "/SiteScope/";

      vers = eregmatch(pattern:'header-login".*SiteScope ([0-9.]+)[^>]*>', string:res);
      if(!isnull(vers[1])) {
        version = vers[1];
        concl = vers[0];
      }
    }
  }

  set_kb_item(name:"www/" + port + "/hpsitescope", value:vers);

  cpe = build_cpe(value:version, exp:"([0-9.]+)", base:"cpe:/a:hp:sitescope:");
  if(!cpe)
    cpe = "cpe:/a:hp:sitescope";

  register_product(cpe:cpe, location:dir, port:port, service:"www");
  log_message(data:build_detection_report(app:"HP SiteScope",
                                          version:version,
                                          install:dir,
                                          cpe:cpe,
                                          concluded:concl),
              port:port);
  exit(0);
}
