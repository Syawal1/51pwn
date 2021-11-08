##############################################################################
# OpenVAS Vulnerability Test
#
# Netautor Professional 'login2.php' Cross Site Scripting Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.902316");
  script_version("2020-08-24T15:18:35+0000");
  script_tag(name:"last_modification", value:"2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2010-10-05 07:29:45 +0200 (Tue, 05 Oct 2010)");
  script_cve_id("CVE-2010-3489");
  script_bugtraq_id(43290);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("Netautor Professional 'login2.php' Cross Site Scripting Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/41475");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/1009-exploits/ZSL-2010-4964.txt");
  script_xref(name:"URL", value:"http://www.zeroscience.mk/en/vulnerabilities/ZSL-2010-4964.php");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"insight", value:"The flaw is due to the input passed to the 'goback' parameter in
  'netautor/napro4/home/login2.php' is not properly sanitised before being returned to the user.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"This host is running Netautor Professional and is prone Cross
  Site Scripting Vulnerability.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute
  arbitrary HTML and script code in a user's browser session in the context of an affected site.");

  script_tag(name:"affected", value:"Netautor Professional version 5.5.0 and prior");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_app");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("misc_func.inc");

port = http_get_port(default:80);

if(!http_can_host_php(port:port))
  exit(0);

vt_strings = get_vt_strings();

foreach dir (make_list_unique("/netautor", "/", http_cgi_dirs(port:port)))
{

  if(dir == "/") dir = "";

  req = http_get(item: dir + "/napro4/index.php", port:port);
  res = http_keepalive_send_recv(port:port, data:req);

  if("<title>Netautor Professional Application Server</title>" >< res)
  {
    req = http_get(item:string(dir , '/napro4/home/login2.php?goback="<script>' +
                                  'alert("', vt_strings["default"], '")</script>'), port:port);
    res = http_keepalive_send_recv(port:port, data:req);

    if(ereg(pattern:"^HTTP/1\.[01] 200", string:res) &&
                    '<script>alert("' + vt_strings["default"] + '")</script>' >< res){
      security_message(port:port);
      exit(0);
    }
  }
}

exit(99);
