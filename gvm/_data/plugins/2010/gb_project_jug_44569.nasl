###############################################################################
# OpenVAS Vulnerability Test
#
# Project Jug Directory Traversal Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.100888");
  script_version("2020-08-24T15:18:35+0000");
  script_tag(name:"last_modification", value:"2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2010-11-02 13:46:58 +0100 (Tue, 02 Nov 2010)");
  script_bugtraq_id(44569);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("Project Jug Directory Traversal Vulnerability");

  script_xref(name:"URL", value:"https://www.securityfocus.com/bid/44569");
  script_xref(name:"URL", value:"http://www.johnleitch.net/Vulnerabilities/Project.Jug.Directory.Traversal/54");
  script_xref(name:"URL", value:"http://sourceforge.net/p/projectjug/home/");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "httpver.nasl", "os_detection.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 8800);
  script_mandatory_keys("Host/runs_windows");
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Project Jug is prone to a directory-traversal vulnerability because it
  fails to sufficiently sanitize user-supplied input.");

  script_tag(name:"impact", value:"Exploiting this issue will allow an attacker to read files outside
  the webroot directory. Information harvested may aid in launching further attacks.");

  script_tag(name:"affected", value:"Project Jug 1.0.0.0 is vulnerable, other versions may also be
  affected.");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective features,
  remove the product or replace the product by another one.");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("misc_func.inc");
include("host_details.inc");

port = http_get_port(default:8800);

files = traversal_files("windows");

foreach pattern( keys( files ) ) {

  file = files[pattern];

  url = string("/.../.../.../.../.../.../.../.../.../.../", file);

  if(http_vuln_check(port:port, url:url, pattern:pattern)) {
    report = http_report_vuln_url(port:port, url:url);
    security_message(port:port, data:report);
    exit(0);
  }
}

exit(0);
