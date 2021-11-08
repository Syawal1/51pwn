###############################################################################
# OpenVAS Vulnerability Test
#
# PHP 'zend_strtod()' Function Floating-Point Value Denial of Service Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (C) 2011 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.103020");
  script_version("2020-10-20T15:03:35+0000");
  script_tag(name:"last_modification", value:"2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)");
  script_tag(name:"creation_date", value:"2011-01-10 13:28:19 +0100 (Mon, 10 Jan 2011)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2010-4645");
  script_bugtraq_id(45668);
  script_name("PHP 'zend_strtod()' Function Floating-Point Value Denial of Service Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_dependencies("gb_php_detect.nasl");
  script_mandatory_keys("php/installed");

  script_xref(name:"URL", value:"https://www.securityfocus.com/bid/45668");
  script_xref(name:"URL", value:"http://bugs.php.net/bug.php?id=53632");
  script_xref(name:"URL", value:"http://svn.php.net/viewvc/?view=revision&revision=307119");
  script_xref(name:"URL", value:"http://svn.php.net/viewvc?view=revision&revision=307095");
  script_xref(name:"URL", value:"http://www.exploringbinary.com/php-hangs-on-numeric-value-2-2250738585072011e-308/");

  script_tag(name:"impact", value:"Successful attacks will cause applications written in PHP to hang,
  creating a denial-of-service condition.");

  script_tag(name:"affected", value:"PHP 5.3.3 is vulnerable. Other versions may also be affected.");

  script_tag(name:"insight", value:"The vulnerability is due to the Floating-Point Value that exist in zend_strtod function");

  script_tag(name:"solution", value:"Updates are available. Please see the references for more details.");

  script_tag(name:"summary", value:"PHP is prone to a remote denial-of-service vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(isnull(port = get_app_port(cpe:CPE)))
  exit(0);

if(!vers = get_app_version(cpe:CPE, port:port))
  exit(0);

if(version_in_range(version:vers, test_version:"5.3", test_version2:"5.3.4") ||
   version_in_range(version:vers, test_version:"5.2", test_version2:"5.2.16")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"5.2.17/5.3.5");
  security_message(data:report, port:port);
  exit(0);
}

exit(99);
