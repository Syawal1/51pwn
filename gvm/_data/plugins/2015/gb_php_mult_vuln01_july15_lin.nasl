###############################################################################
# OpenVAS Vulnerability Test
#
# PHP Multiple Vulnerabilities - 01 - Jul15 (Linux)
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.805684");
  script_version("2020-10-20T15:03:35+0000");
  script_cve_id("CVE-2015-1353", "CVE-2013-6501");
  script_bugtraq_id(72267, 72530);
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)");
  script_tag(name:"creation_date", value:"2015-07-23 13:10:57 +0530 (Thu, 23 Jul 2015)");
  script_name("PHP Multiple Vulnerabilities - 01 - Jul15 (Linux)");

  script_tag(name:"summary", value:"This host is installed with PHP and is prone
  to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to,

  - an integer overflow vulnerability in PHP's Calendar Extension Conversion
  functions.

  - a flaw in the cache directory that is due to the program creating files for
  the cache in a predictable manner.");

  script_tag(name:"impact", value:"Successfully exploiting this issue allow
  remote attackers to inject WSDL files and have them be used in place of the
  intended file and unexpected data result while using Calendar Extension
  Conversion functions.");

  script_tag(name:"affected", value:"PHP versions through 5.6.7");

  script_tag(name:"solution", value:"Upgrade to PHP 5.6.8 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1009103");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1185896");
  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2015-03/msg00003.html");

  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("gb_php_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("php/installed", "Host/runs_unixoide");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(isnull(port = get_app_port(cpe:CPE)))
  exit(0);

if(!vers = get_app_version(cpe:CPE, port:port))
  exit(0);

if(vers =~ "^5\.6")
{
  if(version_in_range(version:vers, test_version:"5.6.0", test_version2:"5.6.7"))
  {
    report = 'Installed Version: ' + vers + '\n' +
             'Fixed Version:     ' + '5.6.8' + '\n';
    security_message(data:report, port:port);
    exit(0);
  }
}

exit(99);
