# Copyright (C) 2019 Greenbone Networks GmbH
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

CPE = "cpe:/a:apache:http_server";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.114148");
  script_version("2020-08-03T10:50:13+0000");
  script_tag(name:"last_modification", value:"2020-08-03 10:50:13 +0000 (Mon, 03 Aug 2020)");
  script_tag(name:"creation_date", value:"2019-10-18 15:43:41 +0200 (Fri, 18 Oct 2019)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_cve_id("CVE-2019-9517", "CVE-2019-10081");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Apache HTTP Server 2.4.20 - 2.4.39 Multiple Vulnerabilities (Windows)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("secpod_apache_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("apache/installed", "Host/runs_windows");

  script_tag(name:"summary", value:"Apache HTTP server is prone to multiple vulnerabilities.");

  script_tag(name:"insight", value:"Apache HTTP server is prone to multiple vulnerabilities:

  - A malicious client could perform a DoS attack by flooding a connection with requests and
  basically never reading responses on the TCP connection. Depending on h2 worker dimensioning,
  it was possible to block those with relatively few connections. (CVE-2019-9517)

  - HTTP/2 very early pushes, for example configured with 'H2PushResource', could lead to
  an overwrite of memory in the pushing request's pool, leading to crashes. The memory
  copied is that of the configured push link header values, not data supplied by
  the client. (CVE-2019-10081)");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Apache HTTP server version 2.4.20 to 2.4.39.");

  script_tag(name:"solution", value:"Update to version 2.4.41 or later.");

  script_xref(name:"URL", value:"https://httpd.apache.org/security/vulnerabilities_24.html");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe: CPE))
  exit(0);

if(!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if(version_in_range(version: version, test_version: "2.4.20", test_version2: "2.4.39")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.4.41");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
