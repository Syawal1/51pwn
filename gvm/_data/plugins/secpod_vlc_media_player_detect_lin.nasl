###############################################################################
# OpenVAS Vulnerability Test
#
# VLC Media Player Version Detection (Linux)
#
# Authors:
# Nikita MR <rnikita@secpod.com>
#
# Copyright:
# Copyright (C) 2009 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.900529");
  script_version("2020-03-27T14:05:33+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2020-03-27 14:05:33 +0000 (Fri, 27 Mar 2020)");
  script_tag(name:"creation_date", value:"2009-03-26 11:19:12 +0100 (Thu, 26 Mar 2009)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("VLC Media Player Version Detection (Linux)");

  script_tag(name:"summary", value:"Detects the installed version of
  VLC Media Player version on Linux.

  This script logs in via shh, extracts the version from the binary file.");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  exit(0);
}

include("ssh_func.inc");
include("cpe.inc");
include("host_details.inc");

sock = ssh_login_or_reuse_connection();
if(!sock)
  exit(0);

vlcBinPath = ssh_find_bin(prog_name:"vlc", sock:sock);
foreach binPath (vlcBinPath)
{
  path = chomp(binPath);
  if(!path)
    continue;

  vlcVer = ssh_get_bin_version(full_prog_name:path, version_argv:"--version", ver_pattern:"VLC version ([0-9\.]+[a-z]?)", sock:sock);
  if(vlcVer[1] != NULL)
  {
    set_kb_item(name:"VLCPlayer/Lin/Ver", value:vlcVer[1]);
    ssh_close_connection();

    cpe = build_cpe(value:vlcVer[1], exp:"^([0-9.]+([a-z0-9]+)?)", base:"cpe:/a:videolan:vlc_media_player:");
    if(isnull(cpe))
      cpe = "cpe:/a:videolan:vlc_media_player";

    register_product(cpe:cpe, location: path);

    log_message(data: build_detection_report(app: "VLC Media Player",
                                             version: vlcVer[1],
                                             install: path,
                                             cpe: cpe,
                                             concluded: vlcVer[1]));
    exit(0);
  }
}
ssh_close_connection();
