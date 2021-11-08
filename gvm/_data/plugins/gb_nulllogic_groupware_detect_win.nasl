###############################################################################
# OpenVAS Vulnerability Test
#
# NullLogic Groupware Version Detection
#
# Authors:
# Nikita MR <rnikita@secpod.com>
#
# Copyright:
# Copyright (C) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800905");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2020-08-24T15:18:35+0000");
  script_tag(name:"last_modification", value:"2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2009-07-18 09:37:41 +0200 (Sat, 18 Jul 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("NullLogic Groupware Version Detection");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_get_http_banner.nasl");
  script_mandatory_keys("NullLogic_Groupware/banner");
  script_require_ports("Services/www", 4110);
  script_tag(name:"summary", value:"This script detects the installed version of NullLogic Groupware.");
  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");
include("cpe.inc");
include("host_details.inc");

SCRIPT_DESC = "NullLogic Groupware Version Detection";

ngPort = http_get_port(default:4110);
banner = http_get_remote_headers(port:ngPort);
if("NullLogic Groupware" >!< banner){
  exit(0);
}

ngVer = eregmatch(pattern:"NullLogic Groupware ([0-9.]+)" , string:banner);
if(ngVer[1] != NULL)
{
  set_kb_item(name:"NullLogic-Groupware/Ver", value:ngVer[1]);
  log_message(data:"NullLogic Groupware version " + ngVer[1] +
                         " was detected on the host");

  cpe = build_cpe(value:ngVer[1], exp:"^([0-9.]+)", base:"cpe:/a:nulllogic:groupware:");
  if(!isnull(cpe))
     register_host_detail(name:"App", value:cpe, desc:SCRIPT_DESC);
}
