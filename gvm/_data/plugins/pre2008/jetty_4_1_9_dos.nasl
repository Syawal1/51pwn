# OpenVAS Vulnerability Test
# Description: Jetty < 4.2.19 Denial of Service
#
# Authors:
# Sarju Bhagat <sarju@westpoint.ltd.uk>
# Fixes by Tenable:
#   - added CVE and OSVDB xrefs.
#
# Copyright:
# Copyright (C) 2005 Westpoint Limited
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.17348");
  script_version("2020-02-03T13:52:45+0000");
  script_tag(name:"last_modification", value:"2020-02-03 13:52:45 +0000 (Mon, 03 Feb 2020)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_cve_id("CVE-2004-2381");
  script_bugtraq_id(9917);
  script_xref(name:"OSVDB", value:"4387");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("Jetty < 4.2.19 Denial of Service");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2005 Westpoint Limited");
  script_family("Denial of Service");
  script_dependencies("gb_jetty_detect.nasl");
  script_mandatory_keys("jetty/detected");

  script_tag(name:"solution", value:"Update to the latest version, or apply a patch.");

  script_tag(name:"summary", value:"The remote host is running a version of Jetty which is older than
  4.2.19. The version is vulnerable to a unspecified denial of service.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

CPE = "cpe:/a:eclipse:jetty";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version: version, test_version: "4.2.19" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "4.2.19", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

exit(99);
