###############################################################################
# OpenVAS Vulnerability Test
#
# ISC BIND NXDOMAIN Redirection Denial of Service Vulnerability
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

CPE = "cpe:/a:isc:bind";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807241");
  script_version("2019-12-10T15:03:15+0000");
  script_cve_id("CVE-2016-1284");
  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2019-12-10 15:03:15 +0000 (Tue, 10 Dec 2019)");
  script_tag(name:"creation_date", value:"2016-02-09 13:49:30 +0530 (Tue, 09 Feb 2016)");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_name("ISC BIND NXDOMAIN Redirection Denial of Service Vulnerability");

  script_tag(name:"summary", value:"The host is installed with ISC BIND and is
  prone to remote denial of service vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an error in 'rdataset.c'
  script when nxdomain-redirect is enabled.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to cause denial of service.");

  script_tag(name:"affected", value:"ISC BIND versions 9.9.8-S1 through 9.9.8-S4.");

  script_tag(name:"solution", value:"Upgrade to ISC BIND version 9.9.8-S5 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://kb.isc.org/docs/aa-01348");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("bind_version.nasl");
  script_mandatory_keys("isc/bind/detected");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! infos = get_app_version_and_proto( cpe:CPE, port:port ) ) exit( 0 );

version = infos["version"];
proto = infos["proto"];

if(version_in_range(version:version, test_version:"9.9.8s1", test_version2:"9.9.8s4")) {
  report = report_fixed_ver(installed_version:version, fixed_version: "9.9.8-S5");
  security_message( data:report, port:port, proto:proto );
  exit( 0 );
}

exit( 99 );