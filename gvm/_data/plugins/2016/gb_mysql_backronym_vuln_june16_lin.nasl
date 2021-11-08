###############################################################################
# OpenVAS Vulnerability Test
#
# Oracle MySQL Backronym Vulnerability June16 (Linux)
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
  script_oid("1.3.6.1.4.1.25623.1.0.808064");
  script_version("2020-05-12T13:57:17+0000");
  script_cve_id("CVE-2015-3152");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2020-05-12 13:57:17 +0000 (Tue, 12 May 2020)");
  script_tag(name:"creation_date", value:"2016-06-02 17:05:55 +0530 (Thu, 02 Jun 2016)");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_name("Oracle MySQL Backronym Vulnerability June16 (Linux)");

  script_tag(name:"summary", value:"This host is running Oracle MySQL and is
  prone to an Backronym vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to improper validation
  of MySQL client library when establishing a secure connection to a MySQL
  server using the --ssl option.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  man-in-the-middle attackers to spoof servers via a cleartext-downgrade
  attack.");

  script_tag(name:"affected", value:"Oracle MySQL Server 5.7.2 and earlier
  on Linux.");

  script_tag(name:"solution", value:"Upgrade to version Oracle MySQL Server 5.7.3 or
  later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.ocert.org/advisories/ocert-2015-003.html");
  script_xref(name:"URL", value:"https://duo.com/blog/backronym-mysql-vulnerability");

  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Databases");
  script_dependencies("mysql_version.nasl", "os_detection.nasl");
  script_mandatory_keys("MySQL/installed", "Host/runs_unixoide");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

cpe_list = make_list("cpe:/a:mysql:mysql", "cpe:/a:oracle:mysql");

if(isnull(infos = get_app_port_from_list(cpe_list:cpe_list)))
  exit(0);

cpe = infos["cpe"];
port = infos["port"];

if(!infos = get_app_version_and_location(cpe:cpe, port:port, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"5.7.3")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"5.7.3");
  security_message(data:report, port:port);
  exit(0);
}
