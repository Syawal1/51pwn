##############################################################################
# OpenVAS Vulnerability Test
#
# Joomla! < 3.8.13 Multiple Vulnerabilities
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2018 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:joomla:joomla";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.141582");
  script_version("2019-05-17T10:45:27+0000");
  script_tag(name:"last_modification", value:"2019-05-17 10:45:27 +0000 (Fri, 17 May 2019)");
  script_tag(name:"creation_date", value:"2018-10-10 14:42:36 +0700 (Wed, 10 Oct 2018)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2018-17858", "CVE-2018-17859");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Joomla! < 3.8.13 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("joomla_detect.nasl");
  script_mandatory_keys("joomla/installed");

  script_tag(name:"summary", value:"Joomla! is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Joomla! is prone to multiple vulnerabilities:

  - CSRF hardening in com_installer (CVE-2018-17858)

  - Inadequate checks in com_contact could allowed mail submission in disabled forms (CVE-2018-17859)");

  script_tag(name:"affected", value:"Joomla! CMS versions 2.5.0 through 3.8.12.");

  script_tag(name:"solution", value:"Update to version 3.8.13 or later.");

  script_xref(name:"URL", value:"https://developer.joomla.org/security-centre/755-20181005-core-csrf-hardening-in-com-installer.html");
  script_xref(name:"URL", value:"https://developer.joomla.org/security-centre/751-20181001-core-hardening-com-contact-contact-form.html");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if(!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE)) exit(0);
version = infos['version'];
path = infos['location'];

if (version_in_range(version: version, test_version: "2.5.0", test_version2: "3.8.12")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.8.13", install_path: path);
  security_message(port: port, data: report);
  exit(0);
}

exit(0);