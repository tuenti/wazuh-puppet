# Wazuh App Copyright (C) 2019 Wazuh Inc. (License GPLv2)
# Setup for ossec client
class wazuh::agent(
  # Versioning and package names
  String                  $agent_package_name,
  String                  $agent_package_version,
  String                  $agent_service_name,

  # Authd registration
  String                  $agent_name,
  String                  $agent_group,
  String                  $ossec_auth_agent_password,
  String                  $wazuh_agent_cert,
  Stdlib::Absolutepath    $wazuh_agent_cert_path,
  String                  $wazuh_agent_key,
  Stdlib::Absolutepath    $wazuh_agent_key_path,
  String                  $wazuh_manager_root_ca_pem,
  Stdlib::Absolutepath    $wazuh_manager_root_ca_pem_path,

  # Client connection
  Stdlib::Host            $wazuh_register_endpoint,
  Stdlib::Host            $wazuh_reporting_endpoint,
  Array[String]           $ossec_config_profiles,
  Integer                 $ossec_notify_time,
  Integer                 $ossec_time_reconnect,
  Enum['yes', 'no']       $ossec_auto_restart,
  Enum['aes', 'blowfish'] $ossec_crypto_method,
  Integer[1,100000]       $client_buffer_queue_size,
  Integer[1,1000]         $client_buffer_events_per_second,

  # Templates paths
  String                  $ossec_conf_template               = 'wazuh/wazuh_agent.conf.erb',
  String                  $ossec_rootcheck_template          = 'wazuh/fragments/_rootcheck.erb',
  String                  $ossec_wodle_openscap_template     = 'wazuh/fragments/_wodle_openscap.erb',
  String                  $ossec_wodle_cis_cat_template      = 'wazuh/fragments/_wodle_cis_cat.erb',
  String                  $ossec_wodle_osquery_template      = 'wazuh/fragments/_wodle_osquery.erb',
  String                  $ossec_wodle_syscollector_template = 'wazuh/fragments/_wodle_syscollector.erb',
  String                  $ossec_sca_template                = 'wazuh/fragments/_sca.erb',
  String                  $ossec_syscheck_template           = 'wazuh/fragments/_syscheck.erb',
  String                  $ossec_localfile_template          = 'wazuh/fragments/_localfile.erb',
  String                  $ossec_ruleset                     = 'wazuh/fragments/_ruleset.erb',
  String                  $ossec_auth                        = 'wazuh/fragments/_auth.erb',
  String                  $ossec_cluster                     = 'wazuh/fragments/_cluster.erb',
  String                  $ossec_active_response_template    = 'wazuh/fragments/_default_activeresponse.erb',

  # Windows only
  Stdlib::Absolutepath    $download_path                     = 'C:/',
) inherits wazuh {
  # Installation
  case $::kernel {
    'Linux' : {
      if $wazuh::manage_repo {
        class { 'wazuh::repo':}
        #TODO: case block
        if $::osfamily == 'Debian' {
          Class['wazuh::repo'] -> Class['apt::update'] -> Package[$agent_package_name]
        } elsif $::osfamily == 'Redhat' {
          Class['wazuh::repo'] -> Package[$agent_package_name]
        } else {
          fail('Cannot manage repo for your distro.')
        }
      }
      package { $agent_package_name:
        ensure => $agent_package_version, # lint:ignore:security_package_pinned_version
      }
    }
    'windows' : {
      file { 'wazuh-agent':
          path               => "${download_path}wazuh-agent-${agent_package_version}.msi",
          owner              => 'Administrator',
          group              => 'Administrators',
          mode               => '0774',
          source             => "http://packages.wazuh.com/3.x/windows/wazuh-agent-${agent_package_version}.msi",
          source_permissions => ignore
      }

      if $wazuh::manage_client_keys {
        package { $agent_package_name:
          ensure          => $agent_package_version, # lint:ignore:security_package_pinned_version
          provider        => 'windows',
          source          => "${download_path}/wazuh-agent-${agent_package_version}.msi",
          install_options => [ '/q', "ADDRESS=${wazuh_register_endpoint}", "AUTHD_SERVER=${wazuh_register_endpoint}" ],
          require         => File["${download_path}wazuh-agent-${agent_package_version}.msi"],
        }
      }
      else {
        package { $agent_package_name:
          ensure          => $agent_package_version, # lint:ignore:security_package_pinned_version
          provider        => 'windows',
          source          => "${download_path}wazuh-agent-${agent_package_version}.msi",
          install_options => [ '/q' ],  # silent installation
          require         => File["${download_path}wazuh-agent-${agent_package_version}.msi"],
        }
      }
    }
    default: { fail('OS not supported') }
  }

  ## ossec.conf generation concats
  concat { 'ossec.conf':
    path    => $wazuh::config_file,
    owner   => $wazuh::config_owner,
    group   => $wazuh::config_group,
    mode    => $wazuh::config_mode,
    require => Package[$agent_package_name],
  }
  concat::fragment {
    default:
      target  => 'ossec.conf';
    'ossec.conf_header':
      order   => 00,
      before  => Service[$agent_service_name],
      content => "<ossec_config>\n";
    'ossec.conf_agent':
      order   => 01,
      before  => Service[$agent_service_name],
      content => template($ossec_conf_template);
  }
  if $wazuh::configure_rootcheck {
    concat::fragment {
        'ossec.conf_rootcheck':
        target  => 'ossec.conf',
        order   => 10,
        before  => Service[$agent_service_name],
        content => template($ossec_rootcheck_template);
    }
  }
  if $wazuh::configure_wodle_openscap {
    concat::fragment {
        'ossec.conf_openscap':
        target  => 'ossec.conf',
        order   => 15,
        before  => Service[$agent_service_name],
        content => template($ossec_wodle_openscap_template);
    }
  }
  if $wazuh::configure_wodle_cis_cat {
    concat::fragment {
        'ossec.conf_cis_cat':
        target  => 'ossec.conf',
        order   => 20,
        before  => Service[$agent_service_name],
        content => template($ossec_wodle_cis_cat_template);
    }
  }
  if $wazuh::configure_wodle_osquery {
    concat::fragment {
        'ossec.conf_osquery':
        target  => 'ossec.conf',
        order   => 25,
        before  => Service[$agent_service_name],
        content => template($ossec_wodle_osquery_template);
    }
  }
  if $wazuh::configure_wodle_syscollector {
    concat::fragment {
        'ossec.conf_syscollector':
        target  => 'ossec.conf',
        order   => 30,
        before  => Service[$agent_service_name],
        content => template($ossec_wodle_syscollector_template);
    }
  }
  if $wazuh::configure_sca {
    concat::fragment {
        'ossec.conf_sca':
        target  => 'ossec.conf',
        order   => 40,
        before  => Service[$agent_service_name],
        content => template($ossec_sca_template);
    }
  }
  if $wazuh::configure_syscheck {
    concat::fragment {
        'ossec.conf_syscheck':
        target  => 'ossec.conf',
        order   => 55,
        before  => Service[$agent_service_name],
        content => template($ossec_syscheck_template);
    }
  }
  if $wazuh::configure_localfile {
    concat::fragment {
        'ossec.conf_localfile':
        target  => 'ossec.conf',
        order   => 65,
        before  => Service[$agent_service_name],
        content => template($ossec_localfile_template);
    }
  }
  if $wazuh::configure_active_response {
    concat::fragment {
        'ossec.conf_active_response':
        target  => 'ossec.conf',
        order   => 90,
        before  => Service[$agent_service_name],
        content => template($ossec_active_response_template);
    }
  }
  concat::fragment {
      'ossec.conf_footer':
      target  => 'ossec.conf',
      order   => 99,
      before  => Service[$agent_service_name],
      content => '</ossec_config>';
  }

  if $wazuh::manage_client_keys {
    if ! defined($wazuh_register_endpoint) {
      fail('The $wazuh_register_endpoint parameter is needed in order to register the Agent.')
    }

    if ($::kernel == 'Linux') {
      #TODO: Is this really Linux only?

      file { $::wazuh::keys_file:
        owner => $wazuh::keys_owner,
        group => $wazuh::keys_group,
        mode  => $wazuh::keys_mode,
      }

      # https://documentation.wazuh.com/current/user-manual/registering/use-registration-service.html#verify-manager-via-ssl
      $agent_auth_base_command = "/var/ossec/bin/agent-auth -m ${wazuh_register_endpoint}"

      if $wazuh_manager_root_ca_pem != undef {
        validate_string($wazuh_manager_root_ca_pem)
        file { '/var/ossec/etc/rootCA.pem':
          owner   => $wazuh::params::keys_owner,
          group   => $wazuh::params::keys_group,
          mode    => $wazuh::params::keys_mode,
          content => $wazuh_manager_root_ca_pem,
          require => Package[$agent_package_name],
        }
        $agent_auth_option_manager = '-v /var/ossec/etc/rootCA.pem'
      }elsif $wazuh_manager_root_ca_pem_path != undef {
        validate_string($wazuh_manager_root_ca_pem)
        $agent_auth_option_manager = "-v ${wazuh_manager_root_ca_pem_path}"
      } else {
        $agent_auth_option_manager = ''  # Avoid errors when compounding final command
      }

      if $agent_name != undef {
        validate_string($agent_name)
        $agent_auth_option_name = "-A \"${agent_name}\""
      }else{
        $agent_auth_option_name = ''
      }

      if $agent_group != undef {
        validate_string($agent_group)
        $agent_auth_option_group = "-G \"${agent_group}\""
      }else{
        $agent_auth_option_group = ''
      }

    # https://documentation.wazuh.com/current/user-manual/registering/use-registration-service.html#verify-agents-via-ssl
    if defined($wazuh_agent_cert) and defined($wazuh_agent_key) {
      file { '/var/ossec/etc/sslagent.cert':
        owner   => $wazuh::keys_owner,
        group   => $wazuh::keys_group,
        mode    => $wazuh::keys_mode,
        content => $wazuh_agent_cert,
        require => Package[$agent_package_name],
      }
      file { '/var/ossec/etc/sslagent.key':
        owner   => $wazuh::keys_owner,
        group   => $wazuh::keys_group,
        mode    => $wazuh::keys_mode,
        content => $wazuh_agent_key,
        require => Package[$agent_package_name],
      }

      $agent_auth_option_agent = '-x /var/ossec/etc/sslagent.cert -k /var/ossec/etc/sslagent.key'
    }

    if ($wazuh_agent_cert_path != undef) and ($wazuh_agent_key_path != undef) {
      validate_string($wazuh_agent_cert_path)
      validate_string($wazuh_agent_key_path)
      $agent_auth_option_agent = "-x ${wazuh_agent_cert_path} -k ${wazuh_agent_key_path}"
    }

    $agent_auth_command = "${agent_auth_base_command} ${agent_auth_option_manager} ${agent_auth_option_name}\
     ${agent_auth_option_group} ${agent_auth_option_agent}"

      if $ossec_auth_agent_password {
        exec { 'agent-auth-with-pwd':
          command => "${agent_auth_command} -P '${ossec_auth_agent_password}'",
          unless  => "/bin/egrep -q '.' ${::wazuh::keys_file}",
          require => Concat['ossec.conf'],
          before  => Service[$agent_service_name],
          }
      } else {
        exec { 'agent-auth-without-pwd':
          command => $agent_auth_command,
          unless  => "/bin/egrep -q '.' ${::wazuh::keys_file}",
          require => Concat['ossec.conf'],
          before  => Service[$agent_service_name],
        }
      }
      if defined($wazuh_reporting_endpoint) {
        service { $agent_service_name:
          ensure    => running,
          enable    => true,
          hasstatus => $wazuh::service_has_status,
          pattern   => $wazuh::agent_service_name,
          provider  => $wazuh::ossec_service_provider,
          require   => Package[$agent_package_name],
        }
      }
    }
  }

  if ( ! $wazuh::manage_client_keys or ( $wazuh_reporting_endpoint == undef ) ){
    service { $agent_service_name:
          ensure    => stopped,
          enable    => false,
          hasstatus => $wazuh::service_has_status,
          pattern   => $agent_service_name,
          provider  => $wazuh::ossec_service_provider,
          require   => Package[$agent_package_name],
    }
  }

  # SELinux
  # Requires selinux module specified in metadata.json
  if ($::osfamily == 'RedHat' and $wazuh::selinux) {
    selinux::module { 'ossec-logrotate':
      ensure    => 'present',
      source_te => 'puppet:///modules/wazuh/ossec-logrotate.te',
    }
  }
  # Manage firewall
  if $wazuh::manage_firewall {
    include firewall
    firewall { '1514 wazuh-agent':
      dport  => $wazuh::ossec_port,
      proto  => $wazuh::ossec_protocol,
      action => 'accept',
      state  => [
        'NEW',
        'RELATED',
        'ESTABLISHED'],
    }
  }
}

