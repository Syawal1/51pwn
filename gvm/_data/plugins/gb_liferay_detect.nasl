# Copyright (C) 2016 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.808730");
  script_version("2020-08-24T15:18:35+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2016-08-01 13:52:04 +0530 (Mon, 01 Aug 2016)");

  script_name("Liferay Portal Detection (HTTP)");

  script_tag(name:"summary", value:"HTTP based detection of Liferay Portal.");

  script_tag(name:"qod_type", value:"remote_banner");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80, 443, 8080);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://www.liferay.com/");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("cpe.inc");
include("host_details.inc");

port = http_get_port(default: 443);

foreach dir(make_list_unique("/", "/Liferay", http_cgi_dirs(port: port))) {

  install = dir;
  if(dir == "/")
    dir = "";

  foreach url(make_list_unique("/", "/web/guest")) {
    url = dir + url;

    res = http_get_cache(port: port, item: url);

    if(res =~ "^HTTP/1\.[01] 200" && "Liferay-Portal:" >< res) {

      set_kb_item(name: "liferay/detected", value: TRUE);

      version = "unknown";

      # Liferay Community Edition Portal 7.0.1 GA2 (Wilberforce / Build 7001 / June 10, 2016)
      # Liferay Portal Community Edition 6.2 CE GA6 (Newton / Build 6205 / January 6, 2016)
      # Liferay DXP Digital Enterprise 7.0.10 GA1 (Wilberforce / Build 7010 / June 15, 2016)
      # Liferay Portal Enterprise Edition 6.2.10 EE GA1 (Newton / Build 6210 / November 1, 2013)
      # Liferay Enterprise Portal 4.3.4 (Owen / Build 4304 / November 5, 2007)
      # Liferay Digital Experience Platform 7.1.10 GA1 (Judson / Build 7110 / July 2, 2018)
      #
      # nb: It's also possible to not expose the version info:
      # Liferay Digital Experience Platform
      vers = eregmatch(pattern: "Liferay-Portal: (Liferay ([a-zA-Z ]+)([0-9.]+)?)( (CE|EE|DE|DXP))?( ([GA0-9]+))?( \(([a-zA-Z]+ / Build [0-9]+ / [a-zA-Z]+ [0-9]+, [0-9]+)\))?",
                      string: res);

      if(!isnull(vers[3])) {
        version = vers[3];
        conclUrl = http_report_vuln_url(port: port, url: url, url_only: TRUE);
      }

      if(!isnull(vers[7]))
        # e.g. 7.0.10.GA1
        version += "." + vers[7];

      if(!isnull(vers[2])) {
        edition = chomp(vers[2]);
        set_kb_item(name: "liferay/" + port + "/edition", value: edition);
      }

      if(!isnull(vers[9]))
        extra = "Build details: " + vers[9];

      cpe = build_cpe(value: tolower(version), exp: "([0-9.a-z]+)", base: "cpe:/a:liferay:liferay_portal:");
      if(!cpe)
        cpe = "cpe:/a:liferay:liferay_portal";

      register_product(cpe: cpe, location: install, port: port, service: "www");

      log_message(data: build_detection_report(app: "Liferay " + edition, version: version, install: install,
                                               cpe: cpe, concluded: vers[0], concludedUrl: conclUrl, extra: extra),
                  port: port);
      exit(0);
    }
  }
}

exit(0);
