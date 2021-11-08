###############################################################################
# OpenVAS Vulnerability Test
#
# pecio cms 'target' Parameter Cross Site Scripting Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.801544");
  script_version("2020-08-24T15:18:35+0000");
  script_tag(name:"last_modification", value:"2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2010-11-23 14:41:37 +0100 (Tue, 23 Nov 2010)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_bugtraq_id(44304);
  script_name("Pecio CMS 'target' Parameter Cross Site Scripting Vulnerability");
  script_xref(name:"URL", value:"http://pecio-cms.com/");
  script_xref(name:"URL", value:"http://secpod.org/blog/?p=137");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/514404");
  script_xref(name:"URL", value:"http://secpod.org/advisories/SECPOD_pecioCMS_XSS.txt");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2010 Greenbone Networks");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"impact", value:"Successful exploitation could allow an attacker to execute
arbitrary HTML code in a user's browser session in the context of a vulnerable
application.");

  script_tag(name:"affected", value:"Pecio CMS v2.0.5 and prior.");

  script_tag(name:"insight", value:"Input passed via the 'target' parameter in 'search' action in
index.php is not properly verified before it is returned to the user. This can
be exploited to execute arbitrary HTML and script code in a user's browser
session in the context of a vulnerable site. This may allow an attacker to
steal cookie-based authentication credentials and launch further attacks.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"The host is running Pecio CMS and is prone to Cross-Site Scripting
  vulnerability.");

  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port(default:80);

foreach dir( make_list_unique( "/pecio-2.0.5", "/pecio-cms", http_cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";

  res = http_get_cache(item:string(dir, "/index.php"), port:port);

  if(">pecio homepage</" >< res)
  {
    if(http_vuln_check(port:port, url:dir + "/index.php?target=search&" +
                       "term=<script>alert('XSS-Test')</script>",
                       pattern:"(<script>alert.'XSS-Test'.</script>)",check_header:TRUE))
    {
      security_message(port:port);
      exit(0);
    }
  }
}
