##############################################################################
# OpenVAS Vulnerability Test
#
# Pilz PNOZmulti Configurator Version Detection (Windows)
#
# Authors:
# Michael Martin <michael.martin@greenbone.net>
#
# Copyright:
# Copyright (C) 2019 Greenbone Networks GmbH, http//www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.107458");
  script_version("2020-08-03T14:04:24+0000");
  script_tag(name:"last_modification", value:"2020-08-03 14:04:24 +0000 (Mon, 03 Aug 2020)");
  script_tag(name:"creation_date", value:"2019-01-19 08:40:31 +0100 (Sat, 19 Jan 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Pilz PNOZmulti Configurator Detection (Windows SMB-Login)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion", "SMB/Windows/Arch");
  script_require_ports(139, 445);

  script_tag(name:"summary", value:"Detects the installed version
  of Pilz PNOZmulti Configurator for Windows.");

  script_xref(name:"URL", value:"https://www.pilz.com");

  script_tag(name:"qod_type", value:"registry");

  exit(0);
}

include("smb_nt.inc");
include("cpe.inc");
include("host_details.inc");
include("secpod_smb_func.inc");

os_arch = get_kb_item("SMB/Windows/Arch");
if(!os_arch)
  exit(0);

if("x86" >< os_arch) {
  key_list = make_list("SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\");
  location = "C:\Program Files\Pilz";
} else if("x64" >< os_arch) {
  key_list = make_list("SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\",
                       "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\");
  location = "C:\Program Files (x86)\Pilz";
}

if(isnull(key_list))
  exit(0);

foreach key(key_list) {
  foreach item(registry_enum_keys(key:key)) {

    appName = registry_get_sz(key:key + item, item:"DisplayName");
    if(!appName || appName !~ "PNOZmulti Configurator")
      continue;

    version = "unknown";
    concluded = appName;

    version = registry_get_sz(key:key + item, item:"DisplayVersion");

    set_kb_item(name:"pilz/pnozmulti_configurator/win/detected", value:TRUE);

    register_and_report_cpe(app:appName, ver:version, concluded:concluded,
                            base:"cpe:/a:pilz:pnozmulti_configurator:", expr:"^([0-9.]+)", insloc:location, regService:"smb-login", regPort:0);
    exit(0);
  }
}

exit(0);
