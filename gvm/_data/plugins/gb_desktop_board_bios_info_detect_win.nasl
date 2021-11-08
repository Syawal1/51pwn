###############################################################################
# OpenVAS Vulnerability Test
#
# BIOS Information Detection (Windows)
#
# Authors:
# Thomas Rotter <Thomas.Rotter@greenbone.net>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.96197");
  script_version("2020-01-07T10:59:33+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2020-01-07 10:59:33 +0000 (Tue, 07 Jan 2020)");
  script_tag(name:"creation_date", value:"2015-04-16 10:59:11 +0100 (Thu, 16 Apr 2015)");
  script_name("BIOS and Hardware Information Detection (Windows)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");

  script_tag(name:"summary", value:"Gathers various BIOS and Hardware related information.

  The script logs in via smb and queries the BIOS related information from the
  Windows registry.");

  script_tag(name:"qod_type", value:"registry");

  exit(0);
}

include("smb_nt.inc");
include("host_details.inc");

SCRIPT_DESC = "BIOS and Hardware Information Detection (Windows)";

bios_ver = registry_get_sz(item:"BIOSVersion", key:"HARDWARE\DESCRIPTION\System\BIOS");
bios_ver = chomp(bios_ver);

bios_vendor = registry_get_sz(item:"BIOSVendor", key:"HARDWARE\DESCRIPTION\System\BIOS");
bios_vendor = chomp(bios_vendor);

base_board_ver = registry_get_sz(item:"BaseBoardVersion", key:"HARDWARE\DESCRIPTION\System\BIOS");
base_board_ver = chomp(base_board_ver);

base_board_manu = registry_get_sz(item:"BaseBoardManufacturer", key:"HARDWARE\DESCRIPTION\System\BIOS");
base_board_manu = chomp(base_board_manu);

base_board_prod_name = registry_get_sz(item:"BaseBoardProduct", key:"HARDWARE\DESCRIPTION\System\BIOS");
base_board_prod_name = chomp(base_board_prod_name);

report = ""; # nb: To make openvas-nasl-lint happy...

if(bios_ver) {
  set_kb_item(name:"DesktopBoards/BIOS/Ver", value:bios_ver);
  report += "BIOS version: " + bios_ver + '\n';
  register_host_detail(name:"BIOSVersion", value:bios_ver, desc:SCRIPT_DESC);
}

if(bios_vendor) {
  set_kb_item(name:"DesktopBoards/BIOS/Vendor", value:bios_vendor);
  report += "BIOS Vendor " + bios_vendor + '\n';
  register_host_detail(name:"BIOSVendor", value:bios_vendor, desc:SCRIPT_DESC);
}

if(base_board_ver) {
  set_kb_item(name:"DesktopBoards/BaseBoard/Ver", value:base_board_ver);
  report += "Base Board version " + base_board_ver + '\n';
  register_host_detail(name:"BaseBoardVersion", value:base_board_ver, desc:SCRIPT_DESC);
}

if(base_board_manu) {
  set_kb_item(name:"DesktopBoards/BaseBoard/Manufacturer", value:base_board_manu);
  report += "Base Board Manufacturer " + base_board_manu + '\n';
  register_host_detail(name:"BaseBoardManufacturer", value:base_board_manu, desc:SCRIPT_DESC);
}

if(base_board_prod_name) {
  set_kb_item(name:"DesktopBoards/BaseBoard/ProdName", value:base_board_prod_name);
  report += "Base Board Product Name " + base_board_prod_name + '\n';
  register_host_detail(name:"BaseBoardProduct", value:base_board_prod_name, desc:SCRIPT_DESC);
}

if(report)
  log_message(port:0, data:report);

exit(0);
