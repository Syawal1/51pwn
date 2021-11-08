###############################################################################
# OpenVAS Vulnerability Test
#
# Trend Micro Smart Protection Server Remote Version Detection
#
# Authors:
# Kashinath T <tkashinath@secpod.com>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.811915");
  script_version("2020-08-24T15:18:35+0000");
  script_tag(name:"last_modification", value:"2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2017-10-05 17:44:54 +0530 (Thu, 05 Oct 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Trend Micro Smart Protection Server Detection (HTTP)");

  script_tag(name:"summary", value:"Detection of Trend Micro Smart Protection Server.

  This script performs a HTTP based detection of Trend Micro Smart Protection Server.");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 4343);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://docs.trendmicro.com/en-us/enterprise/smart-protection-server.aspx");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default:4343);

if (!http_can_host_php(port:port))
  exit(0);

res = http_get_cache(item: "/index.php", port: port);

if ("Trend Micro Smart Protection Server" >< res &&
    "Please type your user name and password to access the product console." >< res) {
  version = "unknown";
  build = "unknown";

  set_kb_item(name: "trendmicro/sps/detected", value: TRUE);

  url = "/sysinfo";
  req = http_get(port: port, item: url);
  res = http_keepalive_send_recv(port: port, data: req, bodyonly: TRUE);

  # {"frs_https": "443", "EnableFrs": "1", "EnableFeedback": "0", "EnableWcs": "1", "TMCSSBuild": "1064", "wrs_https": "5275", "wrs_http": "5274", "frs_http": "80", "TMCSSVersion": "3.3", "WizardConfig": "0"}
  vers = eregmatch(pattern: '"TMCSSVersion": "([0-9.]+)"', string: res);
  if (!isnull(vers[1])) {
    version = vers[1];
    concluded = res;
    concUrl = http_report_vuln_url(port: port, url: url, url_only: TRUE);

    bld = eregmatch(pattern: '"TMCSSBuild": "([0-9]+)"', string: res);
    if (!isnull(bld[1]))
      build = bld[1];
  } else {
    url = "/help/en_US.UTF-8/Introduction.html";
    req = http_get(item: url, port: port);
    res = http_keepalive_send_recv(port: port, data: req );

    # webhelp.css?v=331064
    vers = eregmatch(pattern: "\.(css|js)\?v=([0-9]+)", string: res);
    if (!isnull(vers[2])) {
      vers_build = vers[2];
      version = vers_build[0] + "." + vers_build[1];
      build = substr(vers_build, 2);

      concUrl = http_report_vuln_url(port: port, url: url, url_only: TRUE);
      concluded = vers[0];
    }
  }

  if (build != "unknown")
    set_kb_item(name: "trendmicro/sps/build", value: build);

  cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:trendmicro:smart_protection_server:");
  if (!cpe)
    cpe = "cpe:/a:trendmicro:smart_protection_server";

  register_and_report_os(os: "Linux", cpe: "cpe:/o:linux:kernel",
                         desc: "Trend Micro Smart Protection Server Detection (HTTP)", runs_key: "unixoide");

  register_product(cpe: cpe, location: "/", port: port, service: "www");

  log_message(data: build_detection_report(app: "Trend Micro Smart Protection Server", version: version,
                                           patch: build, install: "/", cpe: cpe, concluded: concluded,
                                           concludedUrl: concUrl),
              port: port);
  exit(0);
}

exit(0);
