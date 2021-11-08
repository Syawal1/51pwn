###############################################################################
# OpenVAS Vulnerability Test
#
# PHP Denial of Service Vulnerability - Jun13 (Windows)
#
# Authors:
# Arun Kallavi <karun@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.803677");
  script_version("2020-10-20T15:03:35+0000");
  script_cve_id("CVE-2013-4636");
  script_bugtraq_id(60728);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)");
  script_tag(name:"creation_date", value:"2013-06-25 17:10:23 +0530 (Tue, 25 Jun 2013)");
  script_name("PHP Denial of Service Vulnerability - Jun13 (Windows)");

  script_xref(name:"URL", value:"http://www.php.net/ChangeLog-5.php");
  script_xref(name:"URL", value:"http://bugs.php.net/bug.php?id=64830");
  script_xref(name:"URL", value:"http://www.security-database.com/detail.php?alert=CVE-2013-4636");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("os_detection.nasl", "gb_php_detect.nasl");
  script_mandatory_keys("php/installed", "Host/runs_windows");

  script_tag(name:"impact", value:"Successful exploitation could allow attackers to cause denial of service
  (invalid pointer dereference and application crash) via an MP3 file.");

  script_tag(name:"affected", value:"PHP version before 5.4.X before 5.4.16");

  script_tag(name:"insight", value:"Flaw in 'mget' function in libmagic/softmagic.c, which triggers incorrect
  MIME type detection during access to an finfo object.");

  script_tag(name:"solution", value:"Upgrade to PHP 5.4.16 or later.");

  script_tag(name:"summary", value:"This host is running PHP and is prone denial of service
  vulnerability.");

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

if(vers =~ "^5\.4") {
  if(version_in_range(version:vers, test_version:"5.4", test_version2: "5.4.15")){
    report = report_fixed_ver(installed_version:vers, fixed_version:"5.4.16");
    security_message(data:report, port:port);
    exit(0);
  }
}

exit(99);