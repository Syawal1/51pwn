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
  script_oid("1.3.6.1.4.1.25623.1.0.150261");
  script_version("2020-10-06T07:40:27+0000");
  script_tag(name:"last_modification", value:"2020-10-06 07:40:27 +0000 (Tue, 06 Oct 2020)");
  script_tag(name:"creation_date", value:"2020-05-15 13:19:50 +0000 (Fri, 15 May 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Huawei Data Communication: Deploying IPv4 PIM Register-Policy");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Policy");
  script_dependencies("vrp_current_configuration_interface.nasl", "vrp_current_configuration_section_include_multicast.nasl", "vrp_current_configuration_pim.nasl");
  script_mandatory_keys("Compliance/Launch");

  script_tag(name:"summary", value:"To prevent attacks from invalid REGISTER requests, you can
configure a packet filtering policy to reject the REGISTER requests that do not match the policy.
Configure the ACL referenced by the policy to permit the multicast source to send Register
messages.");

  exit(0);
}

# Check procedure:
# 1. display current-configuration interface: check for interfaces with 'pim sm' command. If no interfaces has 'pim sm' included, check passes.
# 2. display current-configuration | section include multicast routing-enable: check for vpn-interfaces with 'multicast routing-enable' command. If no vpn-instance with 'multicast routing-enable' exist, check fails.
# 3. display current-configuration configuration pim: Check for vpn-instances without 'register-policy'. If no pim view exists, check fails.

include("policy_functions.inc");

port = get_kb_item("huawei/vrp/ssh-login/port");
model = get_kb_item("huawei/vrp/ssh-login/" + port + "/model");
major_version = get_kb_item("huawei/vrp/ssh-login/major_version");
interfaces = get_kb_item("Policy/vrp/current_configuration/interface");
multicast_routing_enable_error = get_kb_item("Policy/vrp/current_configuration/section/include/multicast_routing_enable/error");
public_instance = get_kb_item("Policy/vrp/current_configuration/section/include/multicast_routing_enable/public");
vpn_instances = get_kb_list("Policy/vrp/current_configuration/section/include/multicast_routing_enable/vpn/*");

cmd = "display current-configuration interface; display current-configuration | section include multicast routing-enable; display current-configuration configuration pim";
title = "Deploying IPv4 PIM Register-Policy";
solution = "Deploy the IPv4 PIM register policy.";
test_type = "SSH_Cmd";
default = "Enable";

if(get_kb_item("Policy/vrp/installed/ERROR")){
  value = "Error";
  compliant = "incomplete";
  comment = "No VRP device detected.";
}else if(!model || !major_version){
  value = "Error";
  compliant = "incomplete";
  comment = "Can not determine model or version of VRP device.";
}else if(model =~ "^AR" && major_version =~ "^5"){ # nb: Test doesn't apply to AR devices on VRP V5
  # Don't report anything if test not applicable
  exit(0);
}else if(get_kb_item("Policy/vrp/ssh/ERROR")){
  value = "Error";
  compliant = "incomplete";
  comment = "No SSH connection to VRP device.";
}else if(!interfaces || interfaces == ""){
  value = "Error";
  compliant = "incomplete";
  comment = "Can not get interfaces";
}else{
  # check if 'display current-configuration interface' command has 'pim sm' included
  if(interfaces =~ "pim\s+sm"){
    # check if 'display current-configuration | section include mutlicast routing-enable' has errors
    if(multicast_routing_enable_error == "error"){
      value = "Error";
      compliant = "incomplete";
      comment = "Can not get sections with multicast routing-enable command";
    }else if(multicast_routing_enable_error == "unknown command"){
      value = "Error";
      compliant = "incomplete";
      comment = "Device does not support command: display current-configuration | section include multicast routing-enable";
    }else if(!public_instance && !vpn_instances){
      value = "No multicast routing-enable in current configuration";
      compliant = "yes";
      comment = "Device has no multicast routing-enable in display current-configuration";
    }else{
      # Check, if pim view exists and is not empty
      if(get_kb_item("Policy/vrp/current_configuration/pim/ERROR") || !get_kb_list("Policy/vrp/current_configuration/pim/*")){
        value = "PIM view does not exist";
        compliant = "no";
        comment = "Can not get PIM view.";
      }else{
        # Check for public instance if multicast routing enable is set
        if(public_instance){
          pim_view = get_kb_item("Policy/vrp/current_configuration/pim/pim");
          if(!pim_view){
            public = "not compliant";
          }else if(pim_view !~ "register-policy"){
            public = "not compliant";
          }
        }
        # Check for each interface with 'multicast routing-enable' setting, if pim view of vpn instance has 'register-policy'
        # included.
        if(vpn_instances){
          foreach vpn_instance (keys(vpn_instances)){
            # get name of vpn interface and pim view of vpn interface
            vpn_instance = str_replace(string:vpn_instance, find:"Policy/vrp/current_configuration/section/include/multicast_routing_enable/vpn/", replace:"");
            pim_view_vpn = get_kb_item("Policy/vrp/current_configuration/pim/pim vpn-instance " + vpn_instance);
            if(!pim_view_vpn){
              vpn = "not compliant";
              failed_vpn_instances += " " + vpn_instance;
            }else if(pim_view_vpn !~ "register-policy"){
              vpn = "not compliant";
              failed_vpn_instances += " " + vpn_instance;
            }
          }
        }

        # if public instance has multicast routing-enable but no register-policy in pim view, test fails
        if(public_instance && public == "not compliant"){
          value = "Disable";
          compliant = "no";
          comment = "Public interface has no register-policy set.";
        }

        # if any vpn instance has multicast routing-enable but no register-policy in pim view, test fails
        if(vpn_instances && vpn == "not compliant"){
          compliant = "no";
          value = "Disable";
          comment += "Following VPN instances have no register-policy set: " + failed_vpn_instances;
        }
      }

      if(!compliant){
        compliant = "Yes";
        value = "Enable";
        comment = "All vpn and public instances have register-policy enabled in PIM view.";
      }
    }
  }else{
    value = "Enable";
    comment = "No 'pim sm' found in interfaces.";
    compliant = "yes";
  }
}

policy_reporting(result:value, default:default, compliant:compliant, fixtext:solution,
  type:test_type, test:cmd, info:comment);
policy_set_kbs(type:test_type, cmd:cmd, default:default, solution:solution, title:title,
  value:value, compliant:compliant);

exit(0);
