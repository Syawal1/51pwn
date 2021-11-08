# Copyright (C) 2020 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.113712");
  script_version("2020-07-14T14:24:25+0000");
  script_tag(name:"last_modification", value:"2020-07-14 14:24:25 +0000 (Tue, 14 Jul 2020)");
  script_tag(name:"creation_date", value:"2020-06-29 11:40:59 +0000 (Mon, 29 Jun 2020)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2020-8162", "CVE-2020-8164", "CVE-2020-8165", "CVE-2020-8167");

  script_name("Ruby on Raily < 5.2.4.3, 6.x < 6.0.3.1 Multiple Vulnerabilities (Windows)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_rails_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("rails/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"Ruby on Rails is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - The Content-Length parameter of a direct file upload may be modified
    by an attacker to bypass upload limitations.

  - A deserialization vulnerability may allow an attacker to read sensitive information.

  - An attacker may unmarshal user-provided objects in MemCacheStore
    and RedisCacheStore resulting in arbitrary code execution.

  - A cross-site request forgery (CSRF) vulnerability in the rails-ujs module
    may allow an attacker to perform actions in the context of another user.");

  script_tag(name:"affected", value:"Ruby on Rails through version 5.2.4.2 and versions 6.0.0.0 through 6.0.3.0.");

  script_tag(name:"solution", value:"Update to version 5.2.4.3 or 6.0.3.1 respectively.");

  script_xref(name:"URL", value:"https://weblog.rubyonrails.org/2020/5/18/Rails-5-2-4-3-and-6-0-3-1-have-been-released/");
  script_xref(name:"URL", value:"https://hackerone.com/reports/789579");
  script_xref(name:"URL", value:"https://hackerone.com/reports/292797");
  script_xref(name:"URL", value:"https://hackerone.com/reports/413388");
  script_xref(name:"URL", value:"https://hackerone.com/reports/189878");

  exit(0);
}

CPE = "cpe:/a:rubyonrails:rails";

include( "host_details.inc" );
include( "version_func.inc" );

if( isnull( port = get_app_port( cpe: CPE ) ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version: version, test_version: "5.2.4.3" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "5.2.4.3", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

if( version_in_range( version: version, test_version: "6.0.0.0", test_version2: "6.0.3.0" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "6.0.3.1", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
