###############################################################################
# OpenVAS Vulnerability Test
#
# OS Detection Consolidation and Reporting
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
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

include("plugin_feed_info.inc");

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105937");
  script_version("2020-12-01T09:47:59+0000");
  script_tag(name:"last_modification", value:"2020-12-01 13:31:42 +0000 (Tue, 01 Dec 2020)");
  script_tag(name:"creation_date", value:"2016-02-19 11:19:54 +0100 (Fri, 19 Feb 2016)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("OS Detection Consolidation and Reporting");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Product detection");
  # Keep order the same as in host_details.inc. Also add NVTs registering an OS there if adding here.
  # nmap_net.nasl was not added as this is in ACT_SCANNER and doesn't use register_and_report_os yet
  # Keep in sync with os_fingerprint.nasl as well.
  script_dependencies("gb_greenbone_os_consolidation.nasl", "gb_ami_megarac_sp_web_detect.nasl",
                      "gb_apple_mobile_detect.nasl",
                      "gb_vmware_esx_web_detect.nasl", "gb_vmware_esx_snmp_detect.nasl",
                      "gb_ssh_cisco_ios_get_version.nasl", "gb_cisco_cucmim_version.nasl",
                      "gb_cisco_cucm_version.nasl", "gb_cisco_nx_os_version.nasl",
                      "gb_cyclades_detect.nasl", "gb_fortios_detect.nasl",
                      "gb_fortimail_consolidation.nasl",
                      "gb_cisco_esa_version.nasl", "gb_cisco_wsa_version.nasl",
                      "gb_cisco_csma_version.nasl", "gb_cisco_ip_phone_detect.nasl",
                      "gb_cisco_ios_xr_version.nasl", "gb_ssh_junos_get_version.nasl",
                      "gb_palo_alto_panOS_version.nasl", "gb_screenos_version.nasl",
                      "gb_extremeos_snmp_detect.nasl", "gb_tippingpoint_sms_consolidation.nasl",
                      "gb_cisco_asa_version_snmp.nasl", "gb_cisco_asa_version.nasl",
                      "gb_cisco_asa_detect.nasl",
                      "gb_arista_eos_snmp_detect.nasl", "gb_netgear_prosafe_consolidation.nasl",
                      "gb_netgear_wnap_consolidation.nasl",
                      "gb_hirschmann_consolidation.nasl", "gb_phoenix_fl_comserver_web_detect.nasl",
                      "gb_geneko_router_consolidation.nasl",
                      "gb_option_cloudgate_consolidation.nasl", "gb_mikrotik_router_routeros_consolidation.nasl",
                      "gb_gpon_home_router_detect.nasl", "gb_zhone_znid_gpon_consolidation.nasl",
                      "gb_teltonika_router_http_detect.nasl", "gb_3com_officeconnect_vpn_firewall_detect.nasl",
                      "gb_axis_network_cameras_ftp_detect.nasl",
                      "gb_xenserver_version.nasl", "gb_cisco_ios_xe_version.nasl",
                      "gb_cisco_nam_consolidation.nasl", "gb_cisco_small_business_switch_consolidation.nasl",
                      "gb_sophos_xg_detect.nasl", "gb_sophos_xg_detect_userportal.nasl",
                      "gb_mcafee_email_gateway_version.nasl", "gb_brocade_netiron_snmp_detect.nasl",
                      "gb_brocade_fabricos_consolidation.nasl",
                      "gb_arubaos_detect.nasl", "gb_cyberoam_umt_ngfw_detect.nasl",
                      "gb_aerohive_hiveos_detect.nasl", "gb_qnap_nas_detect.nasl",
                      "gb_synology_dsm_detect.nasl", "gb_drobo_nas_consolidation.nasl",
                      "gb_buffalo_airstation_detect.nasl",
                      "gb_unraid_http_detect.nasl", "gb_netsweeper_http_detect.nasl",
                      "gb_trendmicro_smart_protection_server_detect.nasl",
                      "gb_barracuda_load_balancer_detect.nasl", "gb_simatic_s7_version.nasl",
                      "gb_simatic_cp_consolidation.nasl", "gb_simatic_scalance_snmp_detect.nasl",
                      "gb_siemens_ruggedcom_consolidation.nasl", "gb_honeywell_xlweb_consolidation.nasl",
                      "ilo_detect.nasl",
                      "gb_watchguard_fireware_detect.nasl", "gb_vibnode_consolidation.nasl",
                      "gb_hyperip_consolidation.nasl", "gb_ruckus_unleashed_http_detect.nasl",
                      "gb_avm_fritz_box_detect.nasl", "gb_avm_fritz_wlanrepeater_consolidation.nasl",
                      "gb_digitalisierungsbox_consolidation.nasl", "gb_lancom_devices_consolidation.nasl",
                      "gb_draytek_vigor_consolidation.nasl", "gb_hp_onboard_administrator_detect.nasl",
                      "gb_cisco_ata_consolidation.nasl", "gb_cisco_spa_voip_device_detect.nasl",
                      "gb_yealink_ip_phone_consolidation.nasl",
                      "gb_dlink_dap_detect.nasl", "gb_dlink_dsl_detect.nasl",
                      "gb_dlink_dns_detect.nasl", "gb_dlink_dir_detect.nasl",
                      "gb_dlink_dwr_detect.nasl", "gb_dlink_dcs_http_detect.nasl",
                      "gb_linksys_devices_consolidation.nasl", "gb_zyxel_ap_http_detect.nasl",
                      "gb_wd_mycloud_consolidation.nasl", "gb_sangoma_nsc_detect.nasl",
                      "gb_intelbras_ncloud_devices_http_detect.nasl", "gb_netapp_data_ontap_consolidation.nasl",
                      "gb_emc_isilon_onefs_consolidation.nasl", "gb_brickcom_network_camera_detect.nasl",
                      "gb_ricoh_printer_consolidation.nasl", "gb_ricoh_iwb_detect.nasl",
                      "gb_lexmark_printer_consolidation.nasl", "gb_toshiba_printer_consolidation.nasl",
                      "gb_xerox_printer_consolidation.nasl", "gb_sato_printer_consolidation.nasl",
                      "gb_codesys_os_detection.nasl",
                      "gb_simatic_hmi_consolidation.nasl", "gb_wago_plc_consolidation.nasl",
                      "gb_rockwell_micrologix_consolidation.nasl", "gb_rockwell_powermonitor_http_detect.nasl",
                      "gb_crestron_cip_detect.nasl", "gb_crestron_ctp_detect.nasl",
                      "gb_beward_ip_cameras_detect_consolidation.nasl", "gb_zavio_ip_cameras_detect.nasl",
                      "gb_tp_link_ip_cameras_detect.nasl", "gb_edgecore_ES3526XA_manager_remote_detect.nasl",
                      "gb_pearl_ip_cameras_detect.nasl",
                      "gb_qsee_ip_camera_detect.nasl", "gb_vicon_industries_network_camera_consolidation.nasl",
                      "gb_riverbed_steelcentral_version.nasl", "gb_riverbed_steelhead_ssh_detect.nasl",
                      "gb_riverbed_steelhead_http_detect.nasl", "gb_dell_sonicwall_sma_sra_consolidation.nasl",
                      "gb_dell_sonicwall_gms_detection.nasl",
                      "gb_grandstream_ucm_consolidation.nasl", "gb_grandstream_gxp_consolidation.nasl",
                      "gb_moxa_edr_devices_web_detect.nasl", "gb_moxa_iologik_devices_consolidation.nasl",
                      "gb_moxa_mgate_consolidation.nasl", "gb_cambium_cnpilot_consolidation.nasl",
                      "gb_westermo_weos_detect.nasl",
                      "gb_windows_cpe_detect.nasl", "gb_huawei_ibmc_consolidation.nasl",
                      "gather-package-list.nasl", "gb_huawei_euleros_consolidation.nasl",
                      "gb_cisco_pis_version.nasl",
                      "gb_checkpoint_fw_version.nasl", "gb_smb_windows_detect.nasl",
                      "gb_nec_communication_platforms_detect.nasl", "gb_inim_smartlan_consolidation.nasl",
                      "gb_dsx_comm_devices_detect.nasl",
                      "gb_ssh_os_detection.nasl", "gb_openvpn_access_server_consolidation.nasl",
                      "gb_cisco_smi_detect.nasl", "gb_pulse_connect_secure_consolidation.nasl",
                      "gb_trend_micro_interscan_web_security_virtual_appliance_consolidation.nasl",
                      "gb_citrix_netscaler_version.nasl", "gb_intel_standard_manageability_detect.nasl",
                      "gb_cisco_ucs_director_consolidation.nasl", "gb_trend_micro_interscan_messaging_security_virtual_appliance_consolidation.nasl",
                      "gb_junos_snmp_version.nasl", "gb_huawei_vrp_network_device_consolidation.nasl", "gb_snmp_os_detection.nasl",
                      "gb_dns_os_detection.nasl", "gb_ftp_os_detection.nasl",
                      "smb_nativelanman.nasl", "gb_ucs_detect.nasl", "gb_cwp_http_detect.nasl",
                      "sw_http_os_detection.nasl", "sw_mail_os_detection.nasl",
                      "sw_telnet_os_detection.nasl", "gb_mysql_mariadb_os_detection.nasl",
                      "apcnisd_detect.nasl", "gb_dahua_devices_detect.nasl",
                      "gb_pptp_os_detection.nasl",
                      "gb_ntp_os_detection.nasl", "remote-detect-MDNS.nasl",
                      "mssqlserver_detect.nasl", "gb_apple_tv_version.nasl",
                      "gb_apple_tv_detect.nasl", "gb_upnp_os_detection.nasl",
                      "gb_sip_os_detection.nasl", "gb_check_mk_agent_detect.nasl",
                      "ms_rdp_detect.nasl", "gb_schneider_clearscada_detect.nasl",
                      "dcetest.nasl", "gb_fsecure_internet_gatekeeper_detect.nasl",
                      "secpod_ocs_inventory_ng_detect.nasl", "gb_hnap_os_detection.nasl",
                      "gb_ident_os_detection.nasl", "gb_pi-hole_detect.nasl",
                      "gb_citrix_xenmobile_detect.nasl",
                      "gb_dropbear_ssh_detect.nasl", "gb_monit_detect.nasl",
                      "gb_rtsp_os_detection.nasl",
                      "gb_nntp_os_detection.nasl", "gb_siemens_sinema_server_detect.nasl",
                      "gb_owa_detect.nasl", "gb_openvas_manager_detect.nasl",
                      "gb_gsa_detect.nasl", "gb_aerospike_consolidation.nasl",
                      "gb_artica_detect.nasl",
                      "gb_android_adb_detect.nasl", "netbios_name_get.nasl",
                      "gb_nmap_os_detection.nasl", "os_fingerprint.nasl");
  if(FEED_NAME == "GSF" || FEED_NAME == "SCM")
    script_dependencies("gsf/gb_crestron_airmedia_consolidation.nasl",
                        "gsf/gb_synetica_datastream_devices_detect_telnet.nasl",
                        "gsf/gb_paloalto_globalprotect_portal_detect.nasl",
                        "gsf/gb_cisco_vision_dynamic_signage_director_detect.nasl",
                        "gsf/gb_tibco_loglogic_http_detect.nasl",
                        "gsf/gb_inea_me-rtu_http_detect.nasl",
                        "gsf/gb_fortios_sslvpn_portal_detect.nasl",
                        "gsf/gb_mult_vendors_wlan_controller_aps_detection.nasl",
                        "gsf/gb_dell_emc_powerconnect_consolidation.nasl",
                        "gsf/gb_cisco_ind_http_detect.nasl",
                        "gsf/gb_cisco_csm_http_detect.nasl",
                        "gsf/gb_silverpeak_appliance_consolidation.nasl",
                        "gsf/gb_ewon_flexy_cosy_http_detect.nasl",
                        "gsf/gb_f5_big_iq_consolidation.nasl",
                        "gsf/gb_optergy_proton_consolidation.nasl",
                        "gsf/gb_unitronics_plc_pcom_detect.nasl",
                        "gsf/gb_sonicwall_email_security_consolidation.nasl",
                        "gsf/gb_ruckus_zonedirector_consolidation.nasl",
                        "gsf/gb_honeywell_ip-ak2_http_detect.nasl",
                        "gsf/gb_siemens_sppa-t3000_app_server_http_detect.nasl",
                        "gsf/gb_timetools_ntp_server_http_detect.nasl",
                        "gsf/gb_aruba_switches_consolidation.nasl",
                        "gsf/gb_trendmicro_apex_central_consolidation.nasl",
                        "gsf/gb_auerswald_compact_sip_detect.nasl",
                        "gsf/gb_beckhoff_ads_udp_detect.nasl",
                        "gsf/gb_apache_activemq_jms_detect.nasl",
                        "gsf/gb_citrix_sharefile_storage_controller_http_detect.nasl",
                        "gsf/gb_konicaminolta_printer_consolidation.nasl",
                        "gsf/gb_ibm_spectrum_protect_plus_consolidation.nasl",
                        "gsf/gb_nimbus_os_detection.nasl",
                        "gsf/gb_secomea_gatemanager_http_detect.nasl",
                        "gsf/gb_symantec_endpoint_protection_manager_http_detect.nasl",
                        "gsf/gb_vxworks_consolidation.nasl",
                        "gsf/gb_spinetix_player_http_detect.nasl",
                        "gsf/gb_spinetix_fusion_http_detect.nasl",
                        "gsf/gb_mobileiron_core_http_detect.nasl",
                        "gsf/gb_mobileiron_sentry_http_detect.nasl",
                        "gsf/gb_bigbluebutton_http_detect.nasl",
                        "gsf/gb_ruckus_iot_controller_http_detect.nasl");

  script_xref(name:"URL", value:"https://community.greenbone.net/c/vulnerability-tests");

  script_tag(name:"summary", value:"This script consolidates the OS information detected by several NVTs and tries to find the best matching OS.

  Furthermore it reports all previously collected information leading to this best matching OS. It also reports possible additional information
  which might help to improve the OS detection.

  If any of this information is wrong or could be improved please consider to report these to the referenced community portal.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");

found_best = FALSE;
found_os = ""; # nb: To make openvas-nasl-lint happy...

# nb: We only want to check the CPE entries
foreach oid( OS_CPE_SRC ) {
  os = get_kb_list( "HostDetails/NVT/" + oid + "/OS" );
  if( ! isnull( os ) ) {
    res = make_list( os );
    foreach entry( res ) {
      # Discard non CPE entries
      if( "cpe:/" >!< entry )
        continue;

      desc = get_kb_item( "HostDetails/NVT/" + oid );

      if( ! found_best ) {

        os_reports = get_kb_list( "os_detection_report/reports/" + oid + "/*" );
        if( ! os_reports )
          continue;

        # Use keys to be able to extract the port and proto later
        foreach key( keys( os_reports ) ) {

          # We need the port and proto for the host_runs kb entry later
          tmp   = split( key, sep:"/", keep:FALSE );
          port  = tmp[3];
          proto = tmp[4];

          # There might be multiple keys/entries for the same port (e.g. http)
          # so using get_kb_list instead() of get_kb_item() here.
          os_reports = get_kb_list( key );
          foreach os_report( os_reports ) {

            # TODO: This is currently only reporting the very first entry of multiple OS detections from the same Detection-VT (e.g. http).
            # We need to find a way to differ in such cases, maybe via a "found_best" list instead of a single variable? In addition there
            # might be additional cases where one HTTP Detection is more detailed then another one.
            if( ! found_best ) {
              report = 'Best matching OS:\n\n' + os_report;
              found_best = TRUE;
              best_match_oid = oid;
              best_match_desc = desc;
              best_match_report = os_report; # To avoid that it will be added to the "Other OS detections" text (see the checks down below)

              # TODO: register_and_report_os() should save this information (together with the CPE) into an own KB entry so that
              # we can use it directly without extracting it from the os_detection_report().
              _best_match_txt = egrep( string:os_report, pattern:'^OS: *[^\r\n]+', icase:FALSE );
              _best_match_txt = chomp( _best_match_txt );
              if( _best_match_txt ) {
                _best_match_txt = eregmatch( string:_best_match_txt, pattern:"OS: *(.+)", icase:FALSE );
                if( _best_match_txt[1] ) {
                  best_match_txt = _best_match_txt[1];
                  _best_match_txt_vers = egrep( string:os_report, pattern:'^Version: *[^\r\n]+', icase:FALSE );
                  _best_match_txt_vers = chomp( _best_match_txt_vers );
                  if( _best_match_txt_vers && _best_match_txt_vers !~ "unknown" ) {
                    _best_match_txt_vers = eregmatch( string:_best_match_txt_vers, pattern:"Version: *(.+)", icase:FALSE );
                    # nb: Avoid adding the version number if it was already included in the "OS:" part (shouldn't happen but just to be sure...)
                    if( _best_match_txt_vers[1] && _best_match_txt_vers[1] >!< best_match_txt )
                      best_match_txt += " " + _best_match_txt_vers[1];
                  }
                }
              } else {
                best_match_txt = "N/A";
              }

              _best_match_cpe = egrep( string:os_report, pattern:'^CPE: *[^\r\n]+', icase:FALSE );
              _best_match_cpe = chomp( _best_match_cpe );
              if( _best_match_cpe ) {
                _best_match_cpe = eregmatch( string:_best_match_cpe, pattern:"CPE: *(.+)", icase:FALSE );
                if( _best_match_cpe[1] )
                  best_match_cpe = _best_match_cpe[1];
              } else {
                best_match_cpe = "N/A";
              }

              host_runs_list = get_kb_list( "os_detection_report/host_runs/" + oid + "/" + port + "/" + proto );

              # We could have multiple host_runs entries on the same port (e.g. http)
              # Choose the first match here
              foreach host_runs( host_runs_list ) {
                if( host_runs == "unixoide" ) {
                  set_key = "Host/runs_unixoide";
                } else if( host_runs == "windows" ) {
                  set_key = "Host/runs_windows";
                } else {
                  # This makes sure that we still scheduling NVTs using Host/runs_unixoide as a fallback
                  set_key = "Host/runs_unixoide";
                }
                if( ! get_kb_item( set_key ) ) {
                  set_kb_item( name:set_key, value:TRUE );
                  report += '\nSetting key "' + set_key + '" based on this information';
                }
              }
            } else {
              if( os_report >!< found_os && os_report >!< best_match_report )
                found_os += os_report + '\n\n';
            }
          }
        }
      } else {
        os_reports = get_kb_list( "os_detection_report/reports/" + oid + "/*" );
        foreach os_report( os_reports ) {
          if( os_report >!< found_os && os_report >!< best_match_report )
            found_os += os_report + '\n\n';
        }
      }
    }
  }
}

if( ! found_best ) {
  report += "No Best matching OS identified. Please see the NVT 'Unknown OS and Service Banner Reporting' (OID: 1.3.6.1.4.1.25623.1.0.108441) ";
  report += "for possible ways to identify this OS.";
  # nb: Setting the runs_key to unixoide makes sure that we still schedule NVTs using Host/runs_unixoide as a fallback
  set_kb_item( name:"Host/runs_unixoide", value:TRUE );
} else {

  # TBD: Move into host_details.nasl?
  detail = best_match_oid + ";" + best_match_desc;
  set_kb_item( name:"HostDetails/OS/BestMatchCPE", value:best_match_cpe );
  set_kb_item( name:"HostDetails/OS/BestMatchCPE/Details", value:detail );
  set_kb_item( name:"HostDetails/OS/BestMatchTXT", value:best_match_txt );
  set_kb_item( name:"HostDetails/OS/BestMatchTXT/Details", value:detail );

  # Store link between os_detection.nasl and gb_os_eol.nasl
  # nb: We don't use the host_details.inc functions in both so we need to call this directly.
  register_host_detail( name:"OS-Detection", value:best_match_cpe );
  register_host_detail( name:best_match_cpe, value:"general/tcp" ); # the port:0 from below
  register_host_detail( name:"port", value:"general/tcp" ); # the port:0 from below
}

if( found_os )
  report += '\n\nOther OS detections (in order of reliability):\n\n' + found_os;

log_message( port:0, data:report );

exit( 0 );
