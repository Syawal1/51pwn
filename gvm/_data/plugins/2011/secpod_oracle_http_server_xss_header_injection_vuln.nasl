###############################################################################
# OpenVAS Vulnerability Test
#
# Oracle HTTP Server 'Expect' Header Cross-Site Scripting Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (C) 2011 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.902526");
  script_version("2020-05-08T08:34:44+0000");
  script_tag(name:"last_modification", value:"2020-05-08 08:34:44 +0000 (Fri, 08 May 2020)");
  script_tag(name:"creation_date", value:"2011-06-24 16:31:03 +0200 (Fri, 24 Jun 2011)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("Oracle HTTP Server 'Expect' Header Cross-Site Scripting Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("Web Servers");
  script_dependencies("gb_oracle_app_server_detect.nasl");
  script_mandatory_keys("oracle/http_server/detected");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary HTML and
  script code in a user's browser session in context of an affected site.");

  script_tag(name:"affected", value:"Oracle HTTP Server for Oracle Application Server 10g Release 2.");

  script_tag(name:"insight", value:"The flaw is caused by improper validation of user-supplied input passed via
  the 'Expect' header from an HTTP request, which allows attackers to execute
  arbitrary HTML and script code on the web server.");

  script_tag(name:"solution", value:"Upgrade to Oracle HTTP Server 11g or later.");

  script_tag(name:"summary", value:"This host is running Oracle HTTP Server and is prone to cross site
  scripting vulnerability.");

  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/17393/");
  script_xref(name:"URL", value:"http://www.securiteam.com/securityreviews/5KP0M1FJ5E.html");
  script_xref(name:"URL", value:"http://www.yaboukir.com/wp-content/bugtraq/XSS_Header_Injection_in_OHS_by_Yasser.pdf");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

CPE = "cpe:/a:oracle:http_server";

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!get_app_location(port:port, cpe:CPE))
  exit(0);

host = http_host_name(port:port);

url = "/index.html";
req = string("GET ", url, " HTTP/1.1\r\n",
             "Host: ", host, "\r\n",
             "Expect: <script>alert('vt-xss-test')</script>\r\n\r\n");
res = http_keepalive_send_recv(port:port, data:req);

if(res =~ "^HTTP/1\.[01] 200" && "Expect: <script>alert('vt-xss-test')</script>" >< res) {
  report  = http_report_vuln_url(port:port, url:url);
  report += '\nAffected header: "Expect"';
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
