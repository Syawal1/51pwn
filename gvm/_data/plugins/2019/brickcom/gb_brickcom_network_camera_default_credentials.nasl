###############################################################################
# OpenVAS Vulnerability Test
#
# Brickcom Network Camera Default Credentials
#
# Authors:
# Thorsten Passfeld <thorsten.passfeld@greenbone.net>
#
# Copyright:
# Copyright (C) 2019 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
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

CPE_PREFIX = "cpe:/h:brickcom";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.114059");
  script_version("2020-05-15T09:07:27+0000");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"2020-05-15 09:07:27 +0000 (Fri, 15 May 2020)");
  script_tag(name:"creation_date", value:"2019-01-03 19:42:47 +0100 (Thu, 03 Jan 2019)");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Default Accounts");
  script_name("Brickcom Network Camera Default Credentials");
  script_dependencies("gb_brickcom_network_camera_detect.nasl", "gb_default_credentials_options.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("brickcom/network_camera/detected");
  script_exclude_keys("default_credentials/disable_default_account_checks");

  script_xref(name:"URL", value:"https://www.brickcom.com/support/faq_contents.php?id=48");

  script_tag(name:"summary", value:"The remote installation of Brickcom's IP camera software is prone to
  a default account authentication bypass vulnerability.");

  script_tag(name:"impact", value:"This issue may be exploited by a remote attacker to gain access
  to sensitive information or modify system configuration.");

  script_tag(name:"insight", value:"The installation of Brickcom's IP camera software is lacking a proper
  password configuration, which makes critical information and actions accessible for people with knowledge
  of the default credentials.");

  script_tag(name:"vuldetect", value:"Checks if a successful login to the IP camera software is possible.");

  script_tag(name:"solution", value:"Change the passwords for user and admin access.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

if(get_kb_item("default_credentials/disable_default_account_checks"))
  exit(0);

include("host_details.inc");
include("misc_func.inc");
include("http_func.inc");

if(!infos = get_app_port_from_cpe_prefix(cpe:CPE_PREFIX, service:"www"))
  exit(0);

port = infos["port"];
CPE  = infos["cpe"];

if(!get_app_location(cpe:CPE, port:port))
  exit(0);

creds = make_array("admin", "admin");

foreach cred(keys(creds)) {

  url = "/";

  #Authorization: Basic YWRtaW46YWRtaW4=
  auth = "Basic " + base64(str: cred + ":" + creds[cred]) ;

  req = http_get_req(port: port, url: url, user_agent: TRUE, add_headers: make_array("Authorization", auth));
  res = http_send_recv(port: port, data: req);

  if("var stateMenu;" >< res || "var viewer=" >< res || "var DeviceProductName=" >< res) {
    VULN = TRUE;
    report += '\nusername: "' + cred + '", password: "' + creds[cred] + '"';
  }
}

if(VULN) {
  report = "It was possible to login with the following default credentials: " + report + '\n\n';
  report += http_report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
