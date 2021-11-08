###############################################################################
# OpenVAS Vulnerability Test
#
# PHP Sessions Subsystem Session Fixation Vulnerability - Aug13 (Windows)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:php:php";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803737");
  script_version("2020-10-20T15:03:35+0000");
  script_cve_id("CVE-2011-4718");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)");
  script_tag(name:"creation_date", value:"2013-08-19 12:03:50 +0530 (Mon, 19 Aug 2013)");
  script_name("PHP Sessions Subsystem Session Fixation Vulnerability - Aug13 (Windows)");

  script_tag(name:"summary", value:"This host is running PHP and is prone to session fixation vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"Upgrade to PHP version 5.5.2 or later.");

  script_tag(name:"insight", value:"PHP contains an unspecified flaw in the Sessions subsystem.");

  script_tag(name:"affected", value:"PHP version prior to 5.5.2 on Windows.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to hijack web sessions by
  specifying a session ID.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/54562");
  script_xref(name:"URL", value:"http://cxsecurity.com/cveshow/CVE-2011-4718");
  script_xref(name:"URL", value:"http://git.php.net/?p=php-src.git;a=commit;h=169b78eb79b0e080b67f9798708eb3771c6d0b2f");
  script_xref(name:"URL", value:"http://git.php.net/?p=php-src.git;a=commit;h=25e8fcc88fa20dc9d4c47184471003f436927cde");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("os_detection.nasl", "gb_php_detect.nasl");
  script_mandatory_keys("php/installed", "Host/runs_windows");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(isnull(port = get_app_port(cpe:CPE)))
  exit(0);

if(!vers = get_app_version(cpe:CPE, port:port))
  exit(0);

if(version_is_less(version:vers, test_version:"5.5.2")){
  report = report_fixed_ver(installed_version:vers, fixed_version:"5.5.2");
  security_message(data:report, port:port);
  exit(0);
}

exit(99);
