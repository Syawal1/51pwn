###############################################################################
# OpenVAS Vulnerability Test
#
# BIOS Information Detection (Linux)
#
# Authors:
# Veerendra GG <veerendragg@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.800163");
  script_version("2020-10-08T10:45:55+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2020-10-08 10:45:55 +0000 (Thu, 08 Oct 2020)");
  script_tag(name:"creation_date", value:"2010-02-11 16:37:59 +0100 (Thu, 11 Feb 2010)");
  script_name("BIOS and Hardware Information Detection (Linux)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_dmidecode_ssh_login_detect.nasl");
  script_mandatory_keys("dmidecode/ssh-login/full_permissions");

  script_tag(name:"summary", value:"Gathers various BIOS and Hardware related information.

  The script logs in via ssh and queries the BIOS and Hardware related information version
  using the command line tool 'dmidecode'. Usually this command requires root privileges to
  execute.");

  script_tag(name:"qod_type", value:"package");

  exit(0);
}

if(!get_kb_item("dmidecode/ssh-login/full_permissions"))
  exit(0);

include("ssh_func.inc");
include("host_details.inc");

sock = ssh_login_or_reuse_connection();
if(!sock)
  exit(0);

SCRIPT_DESC = "BIOS and Hardware Information Detection (Linux)";

bios_ver = ssh_cmd(socket:sock, cmd:"dmidecode -s bios-version", timeout:120);
bios_ver = chomp(bios_ver);

bios_vendor = ssh_cmd(socket:sock, cmd:"dmidecode -s bios-vendor", timeout:120);
bios_vendor = chomp(bios_vendor);

base_board_ver = ssh_cmd(socket:sock, cmd:"dmidecode -s baseboard-version", timeout:120);
base_board_ver = chomp(base_board_ver);

base_board_manu = ssh_cmd(socket:sock, cmd:"dmidecode -s baseboard-manufacturer", timeout:120);
base_board_manu = chomp(base_board_manu);

base_board_prod_name = ssh_cmd(socket:sock, cmd:"dmidecode -s baseboard-product-name", timeout:120);
base_board_prod_name = chomp(base_board_prod_name);

ssh_close_connection();

report = ""; # nb: To make openvas-nasl-lint happy...

if(bios_ver && bios_ver !~ "(command not found|dmidecode:|permission denied)") {
  set_kb_item(name:"DesktopBoards/BIOS/Ver", value:bios_ver);
  report += "BIOS version: " + bios_ver + '\n';
  register_host_detail(name:"BIOSVersion", value:bios_ver, desc:SCRIPT_DESC);
}

if(bios_vendor && bios_vendor !~ "(command not found|dmidecode:|permission denied)") {
  set_kb_item(name:"DesktopBoards/BIOS/Vendor", value:bios_vendor);
  report += "BIOS Vendor: " + bios_vendor + '\n';
  register_host_detail(name:"BIOSVendor", value:bios_vendor, desc:SCRIPT_DESC);
}

if(base_board_ver && base_board_ver !~ "(command not found|dmidecode:|permission denied)") {
  set_kb_item(name:"DesktopBoards/BaseBoard/Ver", value:base_board_ver);
  report += "Base Board version: " + base_board_ver + '\n';
  register_host_detail(name:"BaseBoardVersion", value:base_board_ver, desc:SCRIPT_DESC);
}

if(base_board_manu && base_board_manu !~ "(command not found|dmidecode:|permission denied)") {
  set_kb_item(name:"DesktopBoards/BaseBoard/Manufacturer", value:base_board_manu);
  report += "Base Board Manufacturer: " + base_board_manu + '\n';
  register_host_detail(name:"BaseBoardManufacturer", value:base_board_manu, desc:SCRIPT_DESC);
}

if(base_board_prod_name && base_board_prod_name !~ "(command not found|dmidecode:|permission denied)") {
  set_kb_item(name:"DesktopBoards/BaseBoard/ProdName", value:base_board_prod_name);
  report += "Base Board Product Name: " + base_board_prod_name + '\n';
  register_host_detail(name:"BaseBoardProduct", value:base_board_prod_name, desc:SCRIPT_DESC);
}

if(report)
  log_message(port:0, data:report);

exit(0);
