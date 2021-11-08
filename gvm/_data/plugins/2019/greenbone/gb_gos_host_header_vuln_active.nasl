# Copyright (C) 2019 Greenbone Networks GmbH
#
# SPDX-License-Identifier: GPL-2.0-or-later
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

CPE = "cpe:/o:greenbone:greenbone_os";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108662");
  script_version("2020-08-25T06:01:08+0000");
  script_tag(name:"last_modification", value:"2020-08-25 06:01:08 +0000 (Tue, 25 Aug 2020)");
  script_tag(name:"creation_date", value:"2019-10-10 06:28:14 +0000 (Thu, 10 Oct 2019)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Greenbone OS < 5.0.0 Host Header Injection Vulnerability (Active Check)");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_greenbone_os_consolidation.nasl", "smtp_settings.nasl"); # nb: The setting for get_3rdparty_domain() is currently located in this VT.
  script_mandatory_keys("greenbone/gos/http/detected");

  script_tag(name:"summary", value:"Greenbone OS is prone to an HTTP host header injection vulnerability in
  the Greenbone Security Assistant (GSA) web user interface.");

  script_tag(name:"impact", value:"An attacker can potentially use this vulnerability in a phishing attack.");

  script_tag(name:"affected", value:"All GSM models except GSM 25, GSM 25V and GSM 35 running Greenbone OS
  prior to version 5.0.0.");

  script_tag(name:"solution", value:"Update to version 5.0.0 or later.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_xref(name:"URL", value:"https://www.greenbone.net/en/roadmap-lifecycle/");
  script_xref(name:"URL", value:"https://github.com/greenbone/gsa/pull/318");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");
include("list_array_func.inc");
include("smtp_func.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

if (dir == "/")
  dir = "";

domain = get_3rdparty_domain();
replace = "Host: " + domain;
url = dir + "/";

req = http_get(port: port, item: url);
req = ereg_replace(string: req, pattern: '(Host: [^\r\n]+)', replace: replace);
res = http_keepalive_send_recv(port: port, data: req);
if (!res || res !~ "^HTTP/1\.[01] 303")
  exit(0);

if (found = egrep(string: res, pattern: '<html><body>Code 303 - Redirecting to .+' + domain + '.+<a/></body></html>', icase: TRUE)) {

  info['HTTP Method'] = "GET";
  info['URL'] = http_report_vuln_url(port: port, url: url, url_only: TRUE);
  info['"Host" header'] = replace;

  report  = 'By doing the following request:\n\n';
  report += text_format_table(array: info) + '\n\n';
  report += 'it was possible to redirect to an external ';
  report += 'domain via an HTTP Host header injection attack.';
  report += '\n\nResult:\n\n' + chomp(found);

  expert_info = 'Request:\n'+ req + 'Response:\n' + res + '\n';
  security_message(port: port, data: report, expert_info: expert_info);
  exit(0);
}

exit(99);
