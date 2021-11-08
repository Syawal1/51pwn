###############################################################################
# OpenVAS Vulnerability Test
#
# Chamilo Multiple Remote File Disclosure Vulnerabilities
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103071");
  script_version("2020-08-24T15:18:35+0000");
  script_tag(name:"last_modification", value:"2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2011-02-08 13:20:01 +0100 (Tue, 08 Feb 2011)");
  script_bugtraq_id(46173);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("Chamilo Multiple Remote File Disclosure Vulnerabilities");

  script_xref(name:"URL", value:"https://www.securityfocus.com/bid/46173");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_dependencies("gb_chamilo_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("chamilo/detected");

  script_tag(name:"summary", value:"Dokeos and Chamilo are prone to multiple file-disclosure
  vulnerabilities because they fail to properly sanitize user-supplied input.");

  script_tag(name:"impact", value:"An attacker can exploit these vulnerabilities to view local files in
  the context of the webserver process. This may aid in further attacks.");

  script_tag(name:"affected", value:"Dokeos versions 1.8.6.1 through 2.0 and Chamilo 1.8.7.1 are
  vulnerable. Other versions may also be affected.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the
  disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to
  upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");
include("version_func.inc");

port = http_get_port(default:80);

if(vers = get_version_from_kb(port:port, app:"chamilo")) {
  if(version_is_equal(version: vers, test_version: "1.8.7.1")) {
    security_message(port:port);
    exit(0);
  }
}

exit(0);
