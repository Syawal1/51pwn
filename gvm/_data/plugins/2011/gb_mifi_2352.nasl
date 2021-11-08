###############################################################################
# OpenVAS Vulnerability Test
#
# Novatel Wireless MiFi 2352 Password Information Disclosure Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (C) 2011 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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
  script_oid("1.3.6.1.4.1.25623.1.0.103115");
  script_version("2020-08-24T15:18:35+0000");
  script_tag(name:"last_modification", value:"2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2011-03-10 13:28:46 +0100 (Thu, 10 Mar 2011)");
  script_bugtraq_id(37962);
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:S/C:P/I:N/A:N");
  script_name("Novatel Wireless MiFi 2352 Password Information Disclosure Vulnerability");

  script_xref(name:"URL", value:"https://www.securityfocus.com/bid/37962");
  script_xref(name:"URL", value:"http://www.securitybydefault.com/2010/01/vulnerabilidad-en-modemrouter-3g.html");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"MiFi 2352 is prone to an information-disclosure vulnerability that may
  expose sensitive information.");

  script_tag(name:"impact", value:"Successful exploits will allow authenticated attackers to obtain
  passwords, which may aid in further attacks.");

  script_tag(name:"affected", value:"MiFi 2352 access point firmware 11.47.17 is vulnerable. Other versions
  may also be affected.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since
  the disclosure of this vulnerability. Likely none will be provided anymore. General solution options
  are to upgrade to a newer release, disable respective features, remove the product or replace the
  product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port(default:80);

foreach dir(make_list_unique("/", http_cgi_dirs(port:port))) {

  if(dir == "/") dir = "";
  url = string(dir, "/config.xml.sav");

  if(http_vuln_check(port:port, url:url, pattern:"</WiFi>", extra_check:make_list("<ssid>","<Secure>","<keyindex>"))) {
    report = http_report_vuln_url(port:port, url:url);
    security_message(port:port, data:report);
    exit(0);
  }
}

exit(99);
