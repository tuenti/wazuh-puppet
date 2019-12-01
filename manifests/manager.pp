# Wazuh App Copyright (C) 2019 Wazuh Inc. (License GPLv2)
# Main ossec server config
class wazuh::manager (
  # Versioning and package names
  String                         $server_package_name,
  String                         $server_package_version,
  String                         $server_service_name,

  ## Global
  Array[Stdlib::IP::Address::V4] $ossec_white_list,
  Integer[1,16]                  $ossec_alert_level,
  Integer[16384]                 $ossec_remote_queue_size,

  ## Email
  Boolean                        $ossec_emailnotification,
  Array[String]                  $ossec_emailto,
  String                         $ossec_emailfrom,
  Stdlib::Host                   $ossec_smtp_server,
  Integer                        $ossec_email_maxperhour,
  Integer[1,16]                  $ossec_email_alert_level,
  #TODO: looks deprecated, no doc
  String                         $ossec_email_idsname,

  # Syslog
  Enum['yes', 'no']              $syslog_output,
  Integer                        $syslog_output_level,
  Stdlib::Port                   $syslog_output_port,
  Stdlib::Host                   $syslog_output_server,
  Enum['cef', 'splunk', 'json']  $syslog_output_format,

  # ossec.conf generation parameters
  Boolean                        $configure_vulnerability_detector,
  Boolean                        $configure_command,
  Boolean                        $configure_ruleset,
  Boolean                        $configure_auth,
  Boolean                        $configure_cluster,

  # Vulnerability Detector
  Enum['yes', 'no']              $wodle_vulnerability_detector_disabled,
  Pattern[/\d+[smhd]/]           $wodle_vulnerability_detector_interval,
  Integer                        $wodle_vulnerability_detector_ignore_time,
  Enum['yes', 'no']              $wodle_vulnerability_detector_run_on_start,

  ## Ruleset
  Array[String]                  $decoder_exclude,
  Array[String]                  $rule_exclude,

  # Authd configuration
  Enum['yes', 'no']              $ossec_auth_disabled,
  Stdlib::Port                   $ossec_auth_port,
  Enum['yes', 'no']              $ossec_auth_use_source_ip,
  Enum['yes', 'no']              $ossec_auth_force_insert,
  Integer                        $ossec_auth_force_time,
  Enum['yes', 'no']              $ossec_auth_purge,
  Enum['yes', 'no']              $ossec_auth_limit_maxagents,
  String                         $ossec_auth_ciphers,
  Enum['yes', 'no']              $ossec_auth_ssl_verify_host,
  String                         $ossec_auth_ssl_manager_cert,
  String                         $ossec_auth_ssl_manager_key,
  Enum['yes', 'no']              $ossec_auth_ssl_auto_negotiate,

  # Cluster
  Enum['yes', 'no']              $ossec_cluster_disabled,
  String                         $ossec_cluster_name,
  String                         $ossec_cluster_node_name,
  Enum['master', 'worker']       $ossec_cluster_node_type,
  Pattern[/.{32}/]               $ossec_cluster_key,
  Stdlib::Port                   $ossec_cluster_port,
  Stdlib::IP::Address::V4        $ossec_cluster_bind_addr,
  Array[Stdlib::Host]            $ossec_cluster_nodes,
  Enum['yes', 'no']              $ossec_cluster_hidden,
  #----- End of ossec.conf parameters -------

  Enum['yes', 'no']              $wazuh_manager_verify_manager_ssl,
  String                         $wazuh_manager_server_crt,
  String                         $wazuh_manager_server_key,

  Stdlib::Absolutepath           $processlist_file,
  String                         $processlist_mode,
  String                         $processlist_owner,
  String                         $processlist_group,
  Boolean                        $ossec_integratord_enabled,

  # ossec.conf templates paths
  String                         $ossec_manager_template                      = 'wazuh/wazuh_manager.conf.erb',
  String                         $ossec_rootcheck_template                    = 'wazuh/fragments/_rootcheck.erb',
  String                         $ossec_wodle_openscap_template               = 'wazuh/fragments/_wodle_openscap.erb',
  String                         $ossec_wodle_cis_cat_template                = 'wazuh/fragments/_wodle_cis_cat.erb',
  String                         $ossec_wodle_osquery_template                = 'wazuh/fragments/_wodle_osquery.erb',
  String                         $ossec_wodle_syscollector_template           = 'wazuh/fragments/_wodle_syscollector.erb',
  String                         $ossec_wodle_vulnerability_detector_template = 'wazuh/fragments/_wodle_vulnerability_detector.erb',
  String                         $ossec_sca_template                          = 'wazuh/fragments/_sca.erb',
  String                         $ossec_syscheck_template                     = 'wazuh/fragments/_syscheck.erb',
  String                         $ossec_default_commands_template             = 'wazuh/default_commands.erb',
  String                         $ossec_localfile_template                    = 'wazuh/fragments/_localfile.erb',
  String                         $ossec_ruleset_template                      = 'wazuh/fragments/_ruleset.erb',
  String                         $ossec_auth_template                         = 'wazuh/fragments/_auth.erb',
  String                         $ossec_cluster_template                      = 'wazuh/fragments/_cluster.erb',
  # TODO: this seems to be used for WPK verification, not really 'Active Response', rename?
  String                         $ossec_active_response_template              = 'wazuh/fragments/_default_activeresponse.erb',
  # TODO: currently stub, needs some work
  String                         $local_decoder_template                      = 'wazuh/local_decoder.xml.erb',
  String                         $local_rules_template                        = 'wazuh/local_rules.xml.erb',
  String                         $shared_agent_template                       = 'wazuh/ossec_shared_agent.conf.erb'
) inherits wazuh {
  ## Wazuh Manager on Windows is unsupported
  if $::osfamily == 'windows' {
    fail('The ossec module does not yet support installing the OSSEC HIDS server on Windows')
  }

  ## Check email settings
  ## TODO: should check other values...
  if $ossec_emailnotification and ! defined($ossec_smtp_server) {
    fail('$ossec_emailnotification is enabled but $smtp_server was not set')
  }

  # Manage repo
  if $wazuh::manage_repo {
    # TODO: Allow filtering of EPEL requirement
    class { 'wazuh::repo':}
    if $::osfamily == 'Debian' {
      Class['wazuh::repo'] -> Class['apt::update'] -> Package[$server_package]
    } else {
      Class['wazuh::repo'] -> Package[$server_package]
    }
  }

  # Install and configure Wazuh-manager package
  package { $server_package:
    ensure  => $server_package_version, # lint:ignore:security_package_pinned_version
  }

  file {
    default:
      owner   => $wazuh::config_owner,
      group   => $wazuh::config_group,
      mode    => $wazuh::config_mode,
      notify  => Service[$server_service],
      require => Package[$server_package];
    #TODO: is this correct?
    $wazuh::manager::shared_agent_config_file:
      validate_cmd => $wazuh::validate_cmd_conf,
      content      => template($shared_agent_template);
    '/var/ossec/etc/rules/local_rules.xml':
      content      => template($local_rules_template);
    '/var/ossec/etc/decoders/local_decoder.xml':
      content      => template($local_decoder_template);
    $wazuh::manager::processlist_file:
      content      => template('wazuh/process_list.erb');
  }

  service { $server_service:
    ensure    => running,
    enable    => true,
    hasstatus => $wazuh::service_has_status,
    pattern   => $server_service,
    provider  => $wazuh::ossec_service_provider,
    require   => Package[$server_package],
  }

  ## ossec.conf generation concats
  concat { 'ossec.conf':
    path    => $wazuh::config_file,
    owner   => $wazuh::config_owner,
    group   => $wazuh::config_group,
    mode    => $wazuh::config_mode,
    require => Package[$server_package],
    notify  => Service[$server_service],
  }
  concat::fragment {
    'ossec.conf_header':
      target  => 'ossec.conf',
      order   => 00,
      content => "<ossec_config>\n";
    'ossec.conf_main':
      target  => 'ossec.conf',
      order   => 01,
      content => template($ossec_manager_template);
  }
  if $configure_rootcheck {
    concat::fragment {
        'ossec.conf_rootcheck':
          order   => 10,
          target  => 'ossec.conf',
          content => template($ossec_rootcheck_template);
      }
  }
  if $configure_wodle_openscap {
    concat::fragment {
      'ossec.conf_wodle_openscap':
        order   => 15,
        target  => 'ossec.conf',
        content => template($ossec_wodle_openscap_template);
    }
  }
  if $configure_wodle_cis_cat {
    concat::fragment {
      'ossec.conf_wodle_ciscat':
        order   => 20,
        target  => 'ossec.conf',
        content => template($ossec_wodle_cis_cat_template);
    }
  }
  if $configure_wodle_osquery {
    concat::fragment {
      'ossec.conf_wodle_osquery':
        order   => 25,
        target  => 'ossec.conf',
        content => template($ossec_wodle_osquery_template);
    }
  }
  if $configure_wodle_syscollector {
    concat::fragment {
      'ossec.conf_wodle_syscollector':
        order   => 30,
        target  => 'ossec.conf',
        content => template($ossec_wodle_syscollector_template);
    }
  }
  if $configure_sca {
    concat::fragment {
      'ossec.conf_sca':
        order   => 40,
        target  => 'ossec.conf',
        content => template($ossec_sca_template);
      }
  }
  if $configure_vulnerability_detector {
    concat::fragment {
      'ossec.conf_wodle_vulnerability_detector':
        order   => 45,
        target  => 'ossec.conf',
        content => template($ossec_wodle_vulnerability_detector_template);
    }
    concat::fragment {
      'ossec.conf_wodle_vulnerability_detector_footer':
        order   => 47,
        target  => 'ossec.conf',
        content => '  </wodle>'
    }
  }
  if $configure_syscheck {
    concat::fragment {
      'ossec.conf_syscheck':
        order   => 55,
        target  => 'ossec.conf',
        content => template($ossec_syscheck_template);
    }
  }
  if $configure_command {
    concat::fragment {
          'ossec.conf_command':
            order   => 60,
            target  => 'ossec.conf',
            content => template($ossec_default_commands_template);
      }
  }
  if $configure_localfile {
    concat::fragment {
      'ossec.conf_localfile':
        order   => 65,
        target  => 'ossec.conf',
        content => template($ossec_localfile_template);
    }
  }
  if $configure_ruleset {
    concat::fragment {
        'ossec.conf_ruleset':
          order   => 75,
          target  => 'ossec.conf',
          content => template($ossec_ruleset_template);
      }
  }
  if $configure_auth {
    concat::fragment {
        'ossec.conf_auth':
          order   => 80,
          target  => 'ossec.conf',
          content => template($ossec_auth_template);
      }
  }
  if $configure_cluster {
    concat::fragment {
        'ossec.conf_cluster':
          order   => 85,
          target  => 'ossec.conf',
          content => template($ossec_cluster_template);
      }
  }
  if $configure_active_response {
    concat::fragment {
        'ossec.conf_active_response':
          order   => 90,
          target  => 'ossec.conf',
          content => template($ossec_active_response_template);
      }
  }
  concat::fragment {
    'ossec.conf_footer':
      target  => 'ossec.conf',
      order   => 99,
      content => "</ossec_config>\n";
  }

  if $manage_client_keys  {
    # TODO: ensure the authd service is started if manage_client_keys == authd
    # I think this is fixed and now authd is started automatically...
    # (see https://github.com/wazuh/wazuh/issues/80)

    file { $wazuh::authd_pass_file:
      owner   => $wazuh::keys_owner,
      group   => $wazuh::keys_group,
      mode    => $wazuh::keys_mode,
      content => $ossec_auth_agent_password,
      require => Package[$server_package],
    }
  }

  # Wazuh mTLS
  # https://documentation.wazuh.com/current/user-manual/registering/use-registration-service.html#verify-manager-via-ssl
  if $wazuh_manager_verify_manager_ssl {
    if defined($wazuh_manager_server_crt) and defined($wazuh_manager_server_key) {
      file { '/var/ossec/etc/sslmanager.key':
        content => $wazuh_manager_server_key,
        owner   => 'root',
        group   => 'ossec',
        mode    => '0640',
        require => Package[$server_package],
        notify  => Service[$server_service],
      }

      file { '/var/ossec/etc/sslmanager.cert':
        content => $wazuh_manager_server_crt,
        owner   => 'root',
        group   => 'ossec',
        mode    => '0640',
        require => Package[$server_package],
        notify  => Service[$server_service],
      }
    }
  }

  # Manage firewall
  if $manage_firewall  {
    include firewall
    firewall { '1514 wazuh-manager':
      dport  => $ossec_remote_port,
      proto  => $ossec_remote_protocol,
      action => 'accept',
      state  => [
        'NEW',
        'RELATED',
        'ESTABLISHED'],
    }

    if $ossec_cluster_enabled {
      firewall { '1516 wazuh-manager':
        dport  => $ossec_cluster_port,
        proto  => $ossec_remote_protocol,
        action => 'accept',
        state  => [
          'NEW',
          'RELATED',
          'ESTABLISHED'],
      }
    }
  }
