# Copyright (C) 2020 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

CPE = "cpe:/a:grafana:grafana";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.144077");
  script_version("2020-06-19T07:07:49+0000");
  script_tag(name:"last_modification", value:"2020-06-19 07:07:49 +0000 (Fri, 19 Jun 2020)");
  script_tag(name:"creation_date", value:"2020-06-08 04:13:50 +0000 (Mon, 08 Jun 2020)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:P");

  script_cve_id("CVE-2020-13379");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Grafana 3.0.1 < 6.7.4, 7.0 < 7.0.2 SSRF Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_grafana_http_detect.nasl");
  script_mandatory_keys("grafana/detected");

  script_tag(name:"summary", value:"Grafana is prone to a server-side request forgery vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The avatar feature in Grafana has an SSRF Incorrect Access Control issue.
  This vulnerability allows any unauthenticated user/client to make Grafana send HTTP requests to any URL and
  return its result to the user/client. This can be used to gain information about the network that Grafana is
  running on.");

  script_tag(name:"affected", value:"Grafana versions 3.0.1 - 7.0.1.");

  script_tag(name:"solution", value:"Update to version 6.7.4, 7.0.2 or later.");

  script_xref(name:"URL", value:"https://community.grafana.com/t/grafana-7-0-2-and-6-7-4-security-update/31408");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_in_range(version: version, test_version: "3.0.1", test_version2: "6.7.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.7.4", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "7.0", test_version2: "7.0.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.0.2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);