###############################################################################
# OpenVAS Vulnerability Test
#
# OpenSC Version Detection (Windows)
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.901174");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2019-12-11T13:33:25+0000");
  script_tag(name:"last_modification", value:"2019-12-11 13:33:25 +0000 (Wed, 11 Dec 2019)");
  script_tag(name:"creation_date", value:"2011-02-01 16:46:08 +0100 (Tue, 01 Feb 2011)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("OpenSC Version Detection (Windows)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);

  script_tag(name:"summary", value:"Detects the installed version of OpenSC on Windows.");

  script_tag(name:"qod_type", value:"registry");

  exit(0);
}

include("smb_nt.inc");
include("secpod_smb_func.inc");
include("cpe.inc");
include("host_details.inc");

if(!osArch = get_kb_item("SMB/Windows/Arch"))
  exit(0);

if(!registry_key_exists(key:"SOFTWARE\OpenSC Project\OpenSC") &&
   !registry_key_exists(key:"SOFTWARE\Wow6432Node\OpenSC Project\OpenSC")) {
  exit(0);
}

if("x86" >< osArch) {
  key_list = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
}

else if("x64" >< osArch) {
  key_list = make_list("SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\",
                       "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\");
}

if(!key_list)
  exit(0);

foreach key(key_list) {
  foreach item(registry_enum_keys(key:key)) {
    name = registry_get_sz(key:key + item, item:"DisplayName");
    if("OpenSC" >< name) {

      concluded = name;
      if(!ver = registry_get_sz(key:key + item, item:"DisplayVersion"))
        ver = "unknown";

      set_kb_item(name:"opensc/win/detected", value:TRUE);

      ## 64 bit apps on 64 bit platform
      if("x64" >< osArch && "Wow6432Node" >!< key) {
        set_kb_item(name:"opensc64/win/detected", value:TRUE);
        register_and_report_cpe(app:"OpenSC", ver:ver, concluded:concluded, base:"cpe:/a:opensc-project:opensc:x64:", expr:"^([0-9.]+)", regService:"smb-login", regPort:0);
      } else {
        register_and_report_cpe(app:"OpenSC", ver:ver, concluded:concluded, base:"cpe:/a:opensc-project:opensc:", expr:"^([0-9.]+)", regService:"smb-login", regPort:0);
      }
    }
  }
}

exit(0);
