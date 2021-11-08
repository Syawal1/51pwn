###############################################################################
# OpenVAS Vulnerability Test
#
# MySQL Stored Procedure Unspecified Vulnerability (Windows)
#
# Authors:
# Kashinath T <tkashinath@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.809815");
  script_version("2020-04-01T10:41:43+0000");
  script_cve_id("CVE-2013-2376", "CVE-2013-1511");
  script_bugtraq_id(59227);
  script_tag(name:"last_modification", value:"2020-04-01 10:41:43 +0000 (Wed, 01 Apr 2020)");
  script_tag(name:"creation_date", value:"2016-11-18 16:53:22 +0530 (Fri, 18 Nov 2016)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("MySQL Stored Procedure Unspecified Vulnerability (Windows)");

  script_tag(name:"summary", value:"The host is running MySQL and is prone to
  multiple unspecified vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Unspecified error in some unknown vectors
  related to Stored Procedure.");

  script_tag(name:"impact", value:"Successful exploitation could allow remote
  attackers to affect confidentiality, integrity, and availability via unknown
  vectors.");

  script_tag(name:"affected", value:"MySQL version 5.5.x before 5.5.31 and
  5.6.x before 5.6.11. on Windows");

  script_tag(name:"solution", value:"Upgrade to MySQL version 5.5.31 or 5.6.11
  or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/53022");
  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/topics/security/cpuapr2013-1899555.html");
  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/topics/security/cpuapr2013-1899555.html#AppendixMSQL");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
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

if(vers =~ "^5\.[56]\.")
{
  if(version_in_range(version:vers, test_version:"5.5.0", test_version2:"5.5.30") ||
     version_in_range(version:vers, test_version:"5.6.0", test_version2:"5.6.10"))
  {
    report = report_fixed_ver(installed_version:vers, fixed_version:"Apply the patch", install_path:path);
    security_message(data:report, port:port);
    exit(0);
  }
}
