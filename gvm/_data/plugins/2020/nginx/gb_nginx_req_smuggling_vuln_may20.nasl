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

CPE = "cpe:/a:nginx:nginx";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.143920");
  script_version("2020-05-18T02:48:31+0000");
  script_tag(name:"last_modification", value:"2020-05-18 02:48:31 +0000 (Mon, 18 May 2020)");
  script_tag(name:"creation_date", value:"2020-05-18 02:42:21 +0000 (Mon, 18 May 2020)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");

  script_cve_id("CVE-2020-12440");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"NoneAvailable");

  script_name("nginx <= 1.18.0 HTTP Request Smuggling Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("nginx_detect.nasl");
  script_mandatory_keys("nginx/installed");

  script_tag(name:"summary", value:"NGINX through allows an HTTP request smuggling attack that can lead to cache
  poisoning, credential hijacking, or security bypass.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"nginx version 1.18.0 and prior.");

  script_tag(name:"solution", value:"No known solution is available as of 18th May, 2020.
  Information regarding this issue will be updated once solution details are available.");

  script_xref(name:"URL", value:"https://gist.github.com/Glassware123/1023720bf4787375a04f32a0c12e956a");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less_equal(version: version, test_version: "1.18.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "None");
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
