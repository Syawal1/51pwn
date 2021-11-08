##############################################################################
# OpenVAS Vulnerability Test
#
# Event Horizon 'modfile.php' Cross Site Scripting and SQL Injection Vulnerabilities
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
  script_oid("1.3.6.1.4.1.25623.1.0.902088");
  script_version("2020-08-24T15:18:35+0000");
  script_tag(name:"last_modification", value:"2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2010-08-02 12:38:17 +0200 (Mon, 02 Aug 2010)");
  script_bugtraq_id(41580);
  script_cve_id("CVE-2010-2854", "CVE-2010-2855");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("Event Horizon 'modfile.php' Cross Site Scripting and SQL Injection Vulnerabilities");
  script_xref(name:"URL", value:"http://secunia.com/advisories/40517");
  script_xref(name:"URL", value:"http://freshmeat.net/projects/eventh/");
  script_xref(name:"URL", value:"http://code.google.com/p/eventh/downloads/list");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("Web application abuses");
  script_dependencies("secpod_event_horizon_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("event_horizon/detected");

  script_tag(name:"insight", value:"The flaw exists due to the improper validation of user supplied data to
  'YourEmail' and 'VerificationNumber' parameters to 'modfile.php' script.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"Upgrade to the Event Horizon version 1.1.11.");

  script_tag(name:"summary", value:"This host is running Event Horizon and is prone cross site
  scripting and SQL injection vulnerabilities.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute arbitrary HTML
  and script code and manipulate SQL queries by injecting arbitrary SQL code
  in a user's browser session in context of an affected site.");

  script_tag(name:"affected", value:"Event Horizon version 1.1.10 and prior.");

  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");
include("version_func.inc");

eventhPort = http_get_port(default:80);

if(!dir = get_dir_from_kb(port:eventhPort, app:"Event/Horizon/Ver"))
 exit(0);

url = string(dir, '/modfile.php?YourEmail=<script>alert("VT-XSS-Testing")</script>');
sndReq = http_get(item:url, port:eventhPort);
rcvRes = http_send_recv(port:eventhPort, data:sndReq);

if(rcvRes =~ "^HTTP/1\.[01] 200" && '<script>alert("VT-XSS-Testing")</script>' >< rcvRes) {
  report = http_report_vuln_url(port:eventhPort, url:url);
  security_message(port:eventhPort, data:report);
  exit(0);
}
