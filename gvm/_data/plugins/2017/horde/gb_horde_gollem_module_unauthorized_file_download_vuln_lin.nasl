###############################################################################
# OpenVAS Vulnerability Test
#
# Horde Gollem Module Unauthorized File Download Vulnerability (Linux)
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
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

CPE = "cpe:/a:horde:gollem";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812240");
  script_version("2020-05-15T08:09:24+0000");
  script_cve_id("CVE-2017-15235");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2020-05-15 08:09:24 +0000 (Fri, 15 May 2020)");
  script_tag(name:"creation_date", value:"2017-12-06 18:23:41 +0530 (Wed, 06 Dec 2017)");
  script_name("Horde Gollem Module Unauthorized File Download Vulnerability (Linux)");
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("gb_horde_gollem_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("horde/gollem/installed", "Host/runs_unixoide");

  script_xref(name:"URL", value:"https://blogs.securiteam.com/index.php/archives/3454");

  script_tag(name:"summary", value:"This host is running Horde Groupware and is
  prone to an unauthorized file download vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to user controlled input is
  not sufficiently sanitized when passed to File Manager (gollem) module.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to bypass Horde authentication for file downloads via a crafted
  'fn' parameter that corresponds to the exact filename.");

  script_tag(name:"affected", value:"The File Manager (gollem) module 3.0.11 in
  Horde Groupware 5.2.21 on Linux.");

  script_tag(name:"solution", value:"Upgrade to latest version of Horde Groupware
  and File Manager (gollem) module.");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less_equal(version:vers, test_version:"3.0.11")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"Upgrade to latest version", install_path:path);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);