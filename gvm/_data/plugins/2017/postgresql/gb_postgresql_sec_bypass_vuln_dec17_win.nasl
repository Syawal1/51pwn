###############################################################################
# OpenVAS Vulnerability Test
#
# PostgreSQL Security Bypass Vulnerability-Dec17 (Windows)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
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

CPE = "cpe:/a:postgresql:postgresql";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812311");
  script_version("2020-01-28T13:26:39+0000");
  script_cve_id("CVE-2017-15099");
  script_bugtraq_id(101781);
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2020-01-28 13:26:39 +0000 (Tue, 28 Jan 2020)");
  script_tag(name:"creation_date", value:"2017-12-04 17:20:41 +0530 (Mon, 04 Dec 2017)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("PostgreSQL Security Bypass Vulnerability-Dec17 (Windows)");

  script_tag(name:"summary", value:"This host is running PostgreSQL and is
  prone to a security bypass vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists as commands 'INSERT .. ON CONFLICT DO UPDATE'
  disclose table contents that the invoker lacks privilege to read.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  authenticated users to bypass access controls on the target system.");

  script_tag(name:"affected", value:"PostgreSQL version 9.5.x before 9.5.10, 9.6.x
  before 9.6.6 and 10.x before 10.1.");

  script_tag(name:"solution", value:"Upgrade to PostgreSQL version 10.1 or 9.6.6
  or 9.5.10 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://www.postgresql.org/about/news/1801");

  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Databases");
  script_dependencies("postgresql_detect.nasl", "secpod_postgresql_detect_lin.nasl", "secpod_postgresql_detect_win.nasl", "os_detection.nasl");
  script_mandatory_keys("postgresql/detected", "Host/runs_windows");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(isnull(port = get_app_port(cpe:CPE)))
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
loc = infos["location"];

if(vers =~ "^9\.5") {
  if(version_is_less(version:vers, test_version:"9.5.10")) {
    fix = "9.5.10";
  }
}

else if(vers =~ "^9\.6") {
  if(version_is_less(version:vers, test_version:"9.6.6")) {
    fix = "9.6.6";
  }
}

else if(vers =~ "^10\.") {
  if(version_is_less(version:vers, test_version:"10.1")) {
    fix = "10.1";
  }
}


if(fix) {
  report = report_fixed_ver(installed_version:vers, fixed_version:fix, install_path:loc);
  security_message(port:port, data: report);
  exit(0);
}

exit(99);
