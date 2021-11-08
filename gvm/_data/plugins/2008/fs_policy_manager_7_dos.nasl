# OpenVAS Vulnerability Test
# Description: F-Secure Policy Manager Server fsmsh.dll module DoS
#
# Authors:
# David Maciejak <david dot maciejak at gmail dot com>
#
# Copyright:
# Copyright (C) 2008 David Maciejak
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.80061");
  script_version("2020-08-24T15:18:35+0000");
  script_tag(name:"last_modification", value:"2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2008-10-24 23:33:44 +0200 (Fri, 24 Oct 2008)");
  script_cve_id("CVE-2007-2964");
  script_bugtraq_id(24233);
  script_xref(name:"OSVDB", value:"36723");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("F-Secure Policy Manager Server fsmsh.dll module DoS");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_copyright("Copyright (C) 2008 David Maciejak");
  script_family("Denial of Service");
  script_dependencies("find_service.nasl", "httpver.nasl", "os_detection.nasl", "global_settings.nasl");
  script_mandatory_keys("Host/runs_windows");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"solution", value:"Upgrade to F-Secure Policy Manager Server 7.01 or later.");

  script_tag(name:"summary", value:"The remote host is running a version a F-Secure Policy Manager Server which
  is vulnerable to a denial of service.");

  script_tag(name:"impact", value:"A malicious user can forge a request to query a MS-DOS device name through the
  'fsmsh.dll' CGI module, which will prevent legitimate users from accessing the service using the Manager Console.");

  script_xref(name:"URL", value:"http://www.f-secure.com/security/fsc-2007-4.shtml");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("host_details.inc");

port = http_get_port(default:80);

# only check FSMSH.DLL version
buf = http_get(item:"/fsms/fsmsh.dll?FSMSCommand=GetVersion", port:port);
r = http_keepalive_send_recv(port:port, data:buf, bodyonly:TRUE);
if(!r)
  exit(0);

if (r =~ "^([0-6]\.|7\.00)") security_message(port);
