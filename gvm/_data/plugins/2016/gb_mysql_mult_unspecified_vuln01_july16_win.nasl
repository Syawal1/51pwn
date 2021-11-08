###############################################################################
# OpenVAS Vulnerability Test
#
# Oracle MySQL Multiple Unspecified Vulnerabilities-01 July16 (Windows)
#
# Authors:
# Tushar Khelge <ktushar@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.808588");
  script_version("2020-10-29T15:35:19+0000");
  script_cve_id("CVE-2016-3477", "CVE-2016-3521", "CVE-2016-3615", "CVE-2016-5440");
  script_bugtraq_id(91902, 91932, 91960, 91953);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2020-10-29 15:35:19 +0000 (Thu, 29 Oct 2020)");
  script_tag(name:"creation_date", value:"2016-07-21 10:49:47 +0530 (Thu, 21 Jul 2016)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Oracle MySQL Multiple Unspecified Vulnerabilities-01 July16 (Windows)");

  script_tag(name:"summary", value:"This host is running Oracle MySQL and is
  prone to multiple unspecified vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple unspecified errors exist in the
  MySQL Server component via unknown vectors related to Server.");

  script_tag(name:"impact", value:"Successful exploitation will allow an
  authenticated remote attacker to affect confidentiality, integrity, and
  availability via unknown vectors.");

  script_tag(name:"affected", value:"Oracle MySQL Server 5.5.49 and earlier,
  5.6.30 and earlier, 5.7.12 and earlier on windows");

  script_tag(name:"solution", value:"Apply the patch from the referenced advisory.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/security-advisory/cpujul2016-2881720.html");

  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Databases");
  script_dependencies("mysql_version.nasl", "os_detection.nasl");
  script_require_ports("Services/mysql", 3306);
  script_mandatory_keys("MySQL/installed", "Host/runs_windows");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

cpe_list = make_list( "cpe:/a:mysql:mysql", "cpe:/a:oracle:mysql" );

if(!infos = get_app_port_from_list(cpe_list:cpe_list))
  exit(0);

cpe = infos["cpe"];
port = infos["port"];

if(!infos = get_app_version_and_location(cpe:cpe, port:port, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(vers =~ "^5\.[5-7]\.")
{
  if(version_in_range(version:vers, test_version:"5.5.0", test_version2:"5.5.49") ||
     version_in_range(version:vers, test_version:"5.6.0", test_version2:"5.6.30") ||
     version_in_range(version:vers, test_version:"5.7.0", test_version2:"5.7.12"))
  {
    report = report_fixed_ver(installed_version:vers, fixed_version:"Apply the patch", install_path:path);
    security_message(data:report, port:port);
    exit(0);
  }
}

