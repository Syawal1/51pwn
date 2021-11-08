###############################################################################
# OpenVAS Vulnerability Test
#
# OpenOffice Version Detection (Linux)
#
# Authors:
# Chandan S <schandan@secpod.com>
#
# Copyright:
# Copyright (C) 2009 SecPod, http://www.secpod.org
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
  script_oid("1.3.6.1.4.1.25623.1.0.900073");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2020-06-22T08:41:58+0000");
  script_tag(name:"last_modification", value:"2020-06-22 08:41:58 +0000 (Mon, 22 Jun 2020)");
  script_tag(name:"creation_date", value:"2009-01-29 15:16:47 +0100 (Thu, 29 Jan 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("OpenOffice Version Detection (Linux)");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  script_tag(name:"summary", value:"The script detects the version of OpenOffice.");
  exit(0);
}

include("ssh_func.inc");
include("cpe.inc");
include("host_details.inc");

SCRIPT_DESC = "OpenOffice Version Detection (Linux)";

sock = ssh_login_or_reuse_connection();
if(!sock)
  exit(0);

openName = ssh_find_file(file_name:"/versionrc", useregex:TRUE, regexpar:"$", sock:sock);
foreach binaryName (openName)
{
  binaryName = chomp(binaryName);
  if("openoffice" >!< binaryName){
    continue;
  }

  openVer = ssh_get_bin_version(full_prog_name:"cat", version_argv:binaryName, ver_pattern:"[0-9]\.[0-9](\.[0-9])?", sock:sock);
  if(openVer[0] != NULL)
  {
    set_kb_item(name:"OpenOffice/Linux/Ver", value:openVer[0]);
    ssh_close_connection();

    cpe = build_cpe(value:openVer[0], exp:"^([0-9.]+)", base:"cpe:/a:openoffice:openoffice.org:");
    if(!isnull(cpe))
      register_host_detail(name:"App", value:cpe, desc:SCRIPT_DESC);

    log_message(data:'Detected OpenOffice version: ' + openVer[0] +
                '\nLocation: ' + binaryName +
                '\n\nConcluded from version identification result:\n' +
                 openVer[max_index(openVer)-1]);

    exit(0);
  }
}
ssh_close_connection();
