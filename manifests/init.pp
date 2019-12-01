# Wazuh App Copyright (C) 2019 Wazuh Inc. (License GPLv2)
# Blank container class
class wazuh (
  ### Generic configuration
  ## Manage repository
  Boolean                     $manage_repo,
  Stdlib::HTTPUrl             $repo_base_url,

  ## Selinux
  Boolean                     $selinux,
  Boolean                     $manage_firewall,
  String                      $validate_cmd_conf,

  ## Service flags
  #unnecessary, shouldn't Puppet autodiscover?
  Enum['redhat', 'systemd']   $service_provider,
  Boolean                     $service_has_status,

  ## Config file
  Stdlib::Absolutepath        $config_file,
  String                      $config_mode,
  String                      $config_owner,
  String                      $config_group,

  ## Remote
  Stdlib::Port                $ossec_remote_port,
  Enum['tcp', 'udp']          $ossec_remote_protocol,
  Enum['secure', 'syslog']    $ossec_remote_connection,

  ## Client Keys
  Boolean                     $manage_client_keys,
  Stdlib::Absolutepath        $keys_file,
  String                      $keys_mode,
  String                      $keys_owner,
  String                      $keys_group,
  Stdlib::Absolutepath        $authd_pass_file,

  ## Authd registration
  String                      $ossec_auth_agent_password,

  ### Modules
  Boolean                     $configure_rootcheck,
  Boolean                     $configure_sca,
  Boolean                     $configure_wodle_openscap,
  Boolean                     $configure_wodle_cis_cat,
  Boolean                     $configure_wodle_osquery,
  Boolean                     $configure_wodle_syscollector,
  Boolean                     $configure_syscheck,
  Boolean                     $configure_localfile,
  Boolean                     $configure_active_response,

  ## RootCheck -- deprecated in favor of SCA
  Enum['yes', 'no']           $ossec_rootcheck_enabled,
  Integer                     $ossec_rootcheck_frequency,
  Enum['yes', 'no']           $ossec_rootcheck_check_files,
  Enum['yes', 'no']           $ossec_rootcheck_check_trojans,
  Enum['yes', 'no']           $ossec_rootcheck_check_dev,
  Enum['yes', 'no']           $ossec_rootcheck_check_sys,
  Enum['yes', 'no']           $ossec_rootcheck_check_pids,
  Enum['yes', 'no']           $ossec_rootcheck_check_if,
  Stdlib::Absolutepath        $ossec_rootcheck_rootkit_files,
  Stdlib::Absolutepath        $ossec_rootcheck_rootkit_trojans,
  Enum['yes', 'no']           $ossec_rootcheck_skip_nfs,

  ## SCA: Security Configuration Assessment
  Enum['yes', 'no']           $ossec_sca_enabled,
  Enum['yes', 'no']           $ossec_sca_scan_on_start,
  Pattern[/\d+[smhd]/]        $ossec_sca_interval,
  Enum['yes', 'no']           $ossec_sca_skip_nfs,

  ## OpenSCAP
  Enum['yes', 'no']           $wodle_openscap_enabled,
  Integer                     $wodle_openscap_timeout,
  Pattern[/\d+[smhd]/]        $wodle_openscap_interval,
  Enum['yes', 'no']           $wodle_openscap_scan_on_start,
  #TODO: type
  Hash                        $wodle_openscap_content,

  ## CIS-CAT
  Enum['yes', 'no']           $wodle_ciscat_enabled,
  Integer                     $wodle_ciscat_timeout,
  Pattern[/\d+[smhd]/]        $wodle_ciscat_interval,
  Enum['yes', 'no']           $wodle_ciscat_scan_on_start,
  String                      $wodle_ciscat_java_path,
  String                      $wodle_ciscat_ciscat_path,

  ## OSquery
  Enum['yes', 'no']           $wodle_osquery_disabled,
  Enum['yes', 'no']           $wodle_osquery_run_daemon,
  Stdlib::Absolutepath        $wodle_osquery_log_path,
  Stdlib::Absolutepath        $wodle_osquery_config_path,
  Enum['yes', 'no']           $wodle_osquery_add_labels,

  ## Syscollector
  Enum['yes', 'no']           $wodle_syscollector_disabled,
  Pattern[/\d+[smhd]/]        $wodle_syscollector_interval,
  Enum['yes', 'no']           $wodle_syscollector_scan_on_start,
  Enum['yes', 'no']           $wodle_syscollector_hardware,
  Enum['yes', 'no']           $wodle_syscollector_os,
  Enum['yes', 'no']           $wodle_syscollector_network,
  Enum['yes', 'no']           $wodle_syscollector_packages,
  Enum['yes', 'no']           $wodle_syscollector_ports,
  Enum['yes', 'no']           $wodle_syscollector_processes,

  ## Syscheck
  Enum['yes', 'no']           $ossec_syscheck_disabled,
  Integer                     $ossec_syscheck_frequency,
  Enum['yes', 'no']           $ossec_syscheck_scan_on_start,
  Enum['yes', 'no']           $ossec_syscheck_alert_new_files,
  Enum['yes', 'no']           $ossec_syscheck_auto_ignore,
  Array[Stdlib::Absolutepath] $ossec_syscheck_directories,
  Array[Stdlib::Absolutepath] $ossec_syscheck_ignore,
  Array[String]               $ossec_syscheck_ignore_sregex,
  Array[Stdlib::Absolutepath] $ossec_syscheck_nodiff,
  Enum['yes', 'no']           $ossec_syscheck_skip_nfs,

  ## Localfile
  #TODO: type
  Hash                        $ossec_local_files

  ## Active Response
  #TODO
) {}
