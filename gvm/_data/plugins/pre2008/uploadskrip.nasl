###############################################################################
# OpenVAS Vulnerability Test
#
# AspUpload vulnerability
#
# Authors:
# John Lampe <j_lampe@bellsouth.net>
#
# Copyright:
# Copyright (C) 2003 John Lampe
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
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11746");
  script_version("2020-08-24T15:18:35+0000");
  script_tag(name:"last_modification", value:"2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_cve_id("CVE-2001-0938");
  script_bugtraq_id(3608);
  script_name("AspUpload vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2003 John Lampe");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://marc.info/?l=bugtraq&m=100715294425985&w=2");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the
  disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to
  upgrade to a newer release, disable respective features, remove the product or replace the product by
  another one.");

  script_tag(name:"summary", value:"At least one example script distributed with AspUpload appears to be
  installed on the remote web server.");

  script_tag(name:"impact", value:"AspUpload is an ASP script that supports saving and processing files
  uploading through other web scripts, and the example script likely contains a flaw that allows an
  attacker to upload arbitrary files and store them anywhere on the affected drive.");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_tag(name:"qod_type", value:"remote_active");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port(default:80);
if(!http_can_host_asp(port:port))
  exit(0);

foreach dir(make_list_unique("/", http_cgi_dirs(port:port))) {

  if(dir == "/")
    dir = "";

  url = dir + "/Test11.asp";
  req = http_get(item:url, port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if(!res)
    continue;

  if("UploadScript11.asp" >< res) {
    report = http_report_vuln_url(port:port, url:url);
    security_message(port:port, data:report);
    exit(0);
  }
}

exit(0);
