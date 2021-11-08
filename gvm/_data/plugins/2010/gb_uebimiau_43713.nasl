###############################################################################
# OpenVAS Vulnerability Test
#
# Uebimiau Webmail 'stage' Parameter Local File Include Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (C) 2010 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100844");
  script_version("2020-08-24T15:18:35+0000");
  script_tag(name:"last_modification", value:"2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2010-10-06 12:55:58 +0200 (Wed, 06 Oct 2010)");
  script_bugtraq_id(43713);
  script_tag(name:"cvss_base", value:"5.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_name("Uebimiau Webmail 'stage' Parameter Local File Include Vulnerability");

  script_xref(name:"URL", value:"https://www.securityfocus.com/bid/43713");
  script_xref(name:"URL", value:"http://sourceforge.net/projects/t-dahmail/files/");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("secpod_uebimiau_webmail_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("uebimiau/webmail/detected");

  script_tag(name:"summary", value:"Uebimiau Webmail is prone to a local file-include vulnerability
  because it fails to properly sanitize user-supplied input.");

  script_tag(name:"impact", value:"An attacker can exploit this vulnerability to obtain potentially
  sensitive information and to execute arbitrary local scripts in
  the context of the webserver process. This may allow the attacker
  to compromise the application and the computer, other attacks are also possible.");

  script_tag(name:"affected", value:"Uebimiau Webmail 3.2.0-2.0 is vulnerable, other versions may also
  be affected.");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective features,
  remove the product or replace the product by another one.");

  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");
include("version_func.inc");

port = http_get_port(default:80);

if(vers = get_version_from_kb(port:port, app:"Uebimiau/Webmail")) {
  if(version_is_equal(version: vers, test_version: "3.2.0.2.0")) {
    security_message(port:port);
    exit(0);
  }
}

exit(0);
