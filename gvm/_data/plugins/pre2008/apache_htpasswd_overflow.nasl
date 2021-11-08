# OpenVAS Vulnerability Test
# Description: Apache <= 1.3.33 htpasswd local overflow
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
# based on work from (C) Tenable Network Security
# Fixed by Tenable 26-May-2005:
#   - added BIDs 13777 and 13778
#   - extended banner check to cover 1.3.33 as well.
#   - edited description.
#
# Copyright:
# Copyright (C) 2004 David Maciejak
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
  script_oid("1.3.6.1.4.1.25623.1.0.14771");
  script_version("2020-02-03T13:52:45+0000");
  script_tag(name:"last_modification", value:"2020-02-03 13:52:45 +0000 (Mon, 03 Feb 2020)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:P/A:N");
  script_bugtraq_id(13777, 13778);
  script_name("Apache <= 1.3.33 htpasswd local overflow");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2004 David Maciejak");
  script_family("Privilege escalation");
  script_dependencies("secpod_apache_detect.nasl");
  script_mandatory_keys("apache/installed");

  script_xref(name:"URL", value:"http://archives.neohapsis.com/archives/bugtraq/2004-10/0345.html");

  script_tag(name:"solution", value:"Update to version 1.3.34 or later.");

  script_tag(name:"summary", value:"The remote host appears to be running Apache 1.3.33 or older.

  There is a local buffer overflow in the 'htpasswd' command in these
  versions that may allow a local user to gain elevated privileges if
  'htpasswd' is run setuid or a remote user to run arbitrary commands
  remotely if the script is accessible through a CGI.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

CPE = "cpe:/a:apache:http_server";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less_equal( version: version, test_version: "1.3.33" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "1.3.34", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}


exit(99);
