# Wazuh App Copyright (C) 2019 Wazuh Inc. (License GPLv2)
# Paramas file
class wazuh::params_manager {
  case $::kernel {
    'Linux': {

    # Installation
      $server_package_version                          = '3.10.2-1'
      $manage_repos                                    = true
      $manage_firewall                                 = false

    ### Ossec.conf blocks
      ## Global
      $ossec_emailnotification                         = false
      $ossec_emailto                                   = []
      $ossec_smtp_server                               = 'smtp.example.wazuh.com'
      $ossec_emailfrom                                 = 'ossecm@example.wazuh.com'
      $ossec_email_maxperhour                          = 12
      $ossec_email_idsname                             = undef
      $ossec_white_list                                = ['127.0.0.1','^localhost.localdomain$','10.0.0.2']
      $ossec_alert_level                               = 3
      $ossec_email_alert_level                         = 12
      $ossec_remote_connection                         = 'secure'
      $ossec_remote_port                               = 1514
      $ossec_remote_protocol                           = 'udp'
      $ossec_remote_queue_size                         = 131072

    # ossec.conf generation parameters
      $configure_rootcheck                             = true
      $configure_wodle_openscap                        = true
      $configure_wodle_cis_cat                         = true
      $configure_wodle_osquery                         = true
      $configure_wodle_syscollector                    = true
      $configure_vulnerability_detector                = true
      $configure_sca                                   = true
      $configure_syscheck                              = true
      $configure_command                               = true
      $configure_localfile                             = true
      $configure_ruleset                               = true
      $configure_auth                                  = true
      $configure_cluster                               = true
      $configure_active_response                       = false

    # ossec.conf templates paths
      $ossec_manager_template                          = 'wazuh/wazuh_manager.conf.erb'
      $ossec_rootcheck_template                        = 'wazuh/fragments/_rootcheck.erb'
      $ossec_wodle_openscap_template                   = 'wazuh/fragments/_wodle_openscap.erb'
      $ossec_wodle_cis_cat_template                    = 'wazuh/fragments/_wodle_cis_cat.erb'
      $ossec_wodle_osquery_template                    = 'wazuh/fragments/_wodle_osquery.erb'
      $ossec_wodle_syscollector_template               = 'wazuh/fragments/_wodle_syscollector.erb'
      $ossec_wodle_vulnerability_detector_template     = 'wazuh/fragments/_wodle_vulnerability_detector.erb'
      $ossec_sca_template                              = 'wazuh/fragments/_sca.erb'
      $ossec_syscheck_template                         = 'wazuh/fragments/_syscheck.erb'
      $ossec_default_commands_template                 = 'wazuh/default_commands.erb'
      $ossec_localfile_template                        = 'wazuh/fragments/_localfile.erb'
      $ossec_ruleset_template                          = 'wazuh/fragments/_ruleset.erb'
      $ossec_auth_template                             = 'wazuh/fragments/_auth.erb'
      $ossec_cluster_template                          = 'wazuh/fragments/_cluster.erb'
      #TODO: this seems to be used for WPK verification, not really 'Active Response', rename?
      $ossec_active_response_template                  = 'wazuh/fragments/_default_activeresponse.erb'
      #TODO: currently stub, needs some work
      $local_decoder_template                          = 'wazuh/local_decoder.xml.erb'
      $local_rules_template                            = 'wazuh/local_rules.xml.erb'

      ## Ruleset
      $ossec_ruleset_default_decoder_exclude           = []
      $ossec_ruleset_default_rule_exclude              = ['0215-policy_rules.xml']

      ## Rootcheck
      # deprecated in favor of SCA
      $ossec_rootcheck_enabled                         = false
      $ossec_rootcheck_frequency                       = 43200
      $ossec_rootcheck_check_files                     = true
      $ossec_rootcheck_check_trojans                   = true
      $ossec_rootcheck_check_dev                       = true
      $ossec_rootcheck_check_sys                       = true
      $ossec_rootcheck_check_pids                      = true
      $ossec_rootcheck_check_ports                     = true
      $ossec_rootcheck_check_if                        = true
      $ossec_rootcheck_rootkit_files                   = '/var/ossec/etc/rootcheck/rootkit_files.txt'
      $ossec_rootcheck_rootkit_trojans                 = '/var/ossec/etc/rootcheck/rootkit_trojans.txt'
      $ossec_rootcheck_skip_nfs                        = true

      ## SCA: Security Configuration Assessment
      $ossec_sca_enabled                               = true
      $ossec_sca_scan_on_start                         = true
      $ossec_sca_interval                              = '12h'
      $ossec_sca_skip_nfs                              = true

      ## Authd
      $ossec_auth_enabled                              = false
      $ossec_auth_port                                 = 1515
      $ossec_auth_use_source_ip                        = true
      $ossec_auth_force_insert                         = true
      $ossec_auth_force_time                           = 0
      $ossec_auth_purge                                = true
      $ossec_auth_agent_password                       = undef
      $ossec_auth_limit_maxagents                      = true
      $ossec_auth_ciphers                              = 'HIGH:!ADH:!EXP:!MD5:!RC4:!3DES:!CAMELLIA:@STRENGTH'
      $ossec_auth_ssl_verify_host                      = false
      $ossec_auth_ssl_manager_cert                     = '/var/ossec/etc/sslmanager.cert'
      $ossec_auth_ssl_manager_key                      = '/var/ossec/etc/sslmanager.key'
      $ossec_auth_ssl_auto_negotiate                   = true

      ## Syscheck
      $ossec_syscheck_enabled                          = true
      $ossec_syscheck_frequency                        = '43200'
      $ossec_syscheck_scan_on_start                    = true
      $ossec_syscheck_alert_new_files                  = true
      $ossec_syscheck_auto_ignore                      = false
      $ossec_syscheck_directories                      = ['/etc',
                                              '/usr/bin',
                                              '/usr/sbin',
                                              '/bin',
                                              '/sbin',
                                              '/boot'
                                            ]
      $ossec_syscheck_ignore                           = ['/etc/mtab',
                                              '/etc/hosts.deny',
                                              '/etc/mail/statistics',
                                              '/etc/random-seed',
                                              '/etc/random.seed',
                                              '/etc/adjtime',
                                              '/etc/httpd/logs',
                                              '/etc/utmpx',
                                              '/etc/wtmpx',
                                              '/etc/cups/certs',
                                              '/etc/dumpdates',
                                              '/etc/svc/volatile',
                                              '/sys/kernel/security',
                                              '/sys/kernel/debug',
                                              '/dev/core',
                                            ]
      $ossec_syscheck_ignore_sregex                    = ['^/proc',
                                              '.log$|.swp$'
                                            ]
      $ossec_syscheck_nodiff                           = ['/etc/ssl/private.key']
      $ossec_syscheck_skip_nfs                         = true

      # syslog
      $syslog_output                                   = false
      $syslog_output_level                             = 2
      $syslog_output_port                              = 514
      $syslog_output_server                            = undef
      $syslog_output_format                            = undef

      # Cluster
      $ossec_cluster_enabled                           = false
      $ossec_cluster_name                              = 'wazuh'
      $ossec_cluster_node_name                         = 'node01'
      $ossec_cluster_node_type                         = 'master'
      $ossec_cluster_key                               = 'KEY'
      $ossec_cluster_port                              = '1516'
      $ossec_cluster_bind_addr                         = '0.0.0.0'
      $ossec_cluster_nodes                             = ['NODE_IP']
      $ossec_cluster_hidden                            = false

      ## Wodles

      #openscap
      $wodle_openscap_enabled                          = false
      $wodle_openscap_timeout                          = '1800'
      $wodle_openscap_interval                         = '1d'
      $wodle_openscap_scan_on_start                    = true

      #cis-cat
      $wodle_ciscat_enabled                            = false
      $wodle_ciscat_timeout                            = '1800'
      $wodle_ciscat_interval                           = '1d'
      $wodle_ciscat_scan_on_start                      = true
      $wodle_ciscat_java_path                          = 'wodles/java'
      $wodle_ciscat_ciscat_path                        = 'wodles/ciscat'

      #osquery
      $wodle_osquery_enabled                           = false
      $wodle_osquery_run_daemon                        = true
      $wodle_osquery_log_path                          = '/var/log/osquery/osqueryd.results.log'
      $wodle_osquery_config_path                       = '/etc/osquery/osquery.conf'
      $wodle_osquery_add_labels                        = true

      #syscollector
      $wodle_syscollector_enabled                      = true
      $wodle_syscollector_interval                     = '1h'
      $wodle_syscollector_scan_on_start                = true
      $wodle_syscollector_hardware                     = true
      $wodle_syscollector_os                           = true
      $wodle_syscollector_network                      = true
      $wodle_syscollector_packages                     = true
      $wodle_syscollector_ports                        = true
      $wodle_syscollector_processes                    = true

      #vulnerability-detector
      $wodle_vulnerability_detector_disabled           = true
      $wodle_vulnerability_detector_interval           = '5m'
      $wodle_vulnerability_detector_ignore_time        = '6h'
      $wodle_vulnerability_detector_run_on_start       = true
      #TODO: replace this with some sort of struct?
      $wodle_vulnerability_detector_ubuntu_disabled    = 'yes'
      $wodle_vulnerability_detector_ubuntu_update      = '1h'
      $wodle_vulnerability_detector_redhat_disable     = 'yes'
      $wodle_vulnerability_detector_redhat_update_from = '2010'
      $wodle_vulnerability_detector_redhat_update      = '1h'
      $wodle_vulnerability_detector_debian_9_disable   = 'yes'
      $wodle_vulnerability_detector_debian_9_update    = '1h'

      #----- End of ossec.conf parameters -------
      $ossec_integratord_enabled           = false

      $manage_client_keys                  = true
      $shared_agent_template               = 'wazuh/ossec_shared_agent.conf.erb'

      # mTLS
      $wazuh_manager_verify_manager_ssl    = false
      $wazuh_manager_server_crt            = undef
      $wazuh_manager_server_key            = undef

      ## Wazuh config folders and modes
      $config_file = '/var/ossec/etc/ossec.conf'
      $shared_agent_config_file = '/var/ossec/etc/shared/agent.conf'

      $config_mode = '0640'
      $config_owner = 'root'
      $config_group = 'ossec'

      $keys_file = '/var/ossec/etc/client.keys'
      $keys_mode = '0640'
      $keys_owner = 'root'
      $keys_group = 'ossec'

      $authd_pass_file = '/var/ossec/etc/authd.pass'

      $validate_cmd_conf = '/var/ossec/bin/verify-agent-conf -f %'

      $processlist_file = '/var/ossec/bin/.process_list'
      $processlist_mode = '0640'
      $processlist_owner = 'root'
      $processlist_group = 'ossec'

      case $::osfamily {
        'Debian': {
          $server_service = 'wazuh-manager'
          $server_package = 'wazuh-manager'
          $api_service = 'wazuh-api'
          $api_package = 'wazuh-api'
          $agent_service  = 'wazuh-agent'
          $agent_package  = 'wazuh-agent'
          $service_has_status  = false
          $ossec_service_provider = undef
          $api_service_provider = undef
          $default_local_files = [
            {  'location' => '/var/log/syslog' , 'log_format' => 'syslog'},
            {  'location' => '/var/log/kern.log' , 'log_format' => 'syslog'},
            {  'location' => '/var/log/auth.log' , 'log_format' => 'syslog'},
            {  'location' => '/var/log/dpkg.log', 'log_format' => 'syslog'},
            {  'location' => '/var/ossec/logs/active-responses.log', 'log_format' => 'syslog'},
            {  'location' => '/var/log/messages' , 'log_format' => 'syslog'},
          ]
          case $::lsbdistcodename {
            'xenial': {
              $wodle_openscap_content = {
                'ssg-ubuntu-1604-ds.xml' => {
                  'type' => 'xccdf',
                  profiles => ['xccdf_org.ssgproject.content_profile_common'],
                },'cve-ubuntu-xenial-oval.xml' => {
                  'type' => 'oval'
                }
              }
            }
            'jessie': {
              $wodle_openscap_content = {
                'ssg-debian-8-ds.xml' => {
                  'type' => 'xccdf',
                  profiles => ['xccdf_org.ssgproject.content_profile_common'],
                },
                'cve-debian-8-oval.xml' => {
                  'type' => 'oval',
                }
              }
            }
            'stretch': {
              $wodle_openscap_content = {
                'ssg-debian-9-ds.xml' => {
                  'type' => 'xccdf',
                  profiles => ['xccdf_org.ssgproject.content_profile_common'],
                },
                'cve-debian-9-oval.xml' => {
                  'type' => 'oval',
                }
              }
            }
            /^(wheezy|sid|precise|trusty|vivid|wily|xenial|bionic)$/: {
              $wodle_openscap_content = {}
            }
            default: {
              fail("Module ${module_name} is not supported on ${::operatingsystem}")
            }
          }
        }
        'RedHat': {
          $agent_service  = 'wazuh-agent'
          $agent_package  = 'wazuh-agent'
          $server_service = 'wazuh-manager'
          $server_package = 'wazuh-manager'
          $api_service = 'wazuh-api'
          $api_package = 'wazuh-api'
          $service_has_status  = true
          $default_local_files =[
              {  'location' => '/var/log/audit/audit.log' , 'log_format' => 'audit'},
              {  'location' => '/var/ossec/logs/active-responses.log' , 'log_format' => 'syslog'},
              {  'location' => '/var/log/messages', 'log_format' => 'syslog'},
              {  'location' => '/var/log/secure' , 'log_format' => 'syslog'},
              {  'location' => '/var/log/maillog' , 'log_format' => 'apache'},
          ]
          case $::operatingsystem {
            'Amazon': {
              $ossec_service_provider = 'systemd'
              $api_service_provider = 'systemd'
              # Amazon is based on Centos-6 with some improvements
              # taken from RHEL-7 but uses SysV-Init, not Systemd.
              # Probably best to leave this undef until we can
              # write/find a release-specific file.
              $wodle_openscap_content = {}
            }
            'CentOS': {
              if ( $::operatingsystemrelease =~ /^6.*/ ) {
                $ossec_service_provider = 'redhat'
                $api_service_provider = 'redhat'
                $wodle_openscap_content = {
                  'ssg-centos-6-ds.xml' => {
                    'type' => 'xccdf',
                    profiles => ['xccdf_org.ssgproject.content_profile_pci-dss', 'xccdf_org.ssgproject.content_profile_server',]
                  }
                }
              }
              if ( $::operatingsystemrelease =~ /^7.*/ ) {
                $ossec_service_provider = 'systemd'
                $api_service_provider = 'systemd'
                $wodle_openscap_content = {
                  'ssg-centos-7-ds.xml' => {
                    'type' => 'xccdf',
                    profiles => ['xccdf_org.ssgproject.content_profile_pci-dss', 'xccdf_org.ssgproject.content_profile_common',]
                  }
                }
              }
            }
            /^(RedHat|OracleLinux)$/: {
              if ( $::operatingsystemrelease =~ /^6.*/ ) {
                $ossec_service_provider = 'redhat'
                $api_service_provider = 'redhat'
                $wodle_openscap_content = {
                  'ssg-rhel-6-ds.xml' => {
                    'type' => 'xccdf',
                    profiles => ['xccdf_org.ssgproject.content_profile_pci-dss', 'xccdf_org.ssgproject.content_profile_server',]
                  },
                  'cve-redhat-6-ds.xml' => {
                    'type' => 'xccdf',
                  }
                }
              }
              if ( $::operatingsystemrelease =~ /^7.*/ ) {
                $ossec_service_provider = 'systemd'
                $api_service_provider = 'systemd'
                $wodle_openscap_content = {
                  'ssg-rhel-7-ds.xml' => {
                    'type' => 'xccdf',
                    profiles => ['xccdf_org.ssgproject.content_profile_pci-dss', 'xccdf_org.ssgproject.content_profile_common',]
                  },
                  'cve-redhat-7-ds.xml' => {
                    'type' => 'xccdf',
                  }
                }
              }
            }
            'Fedora': {
              if ( $::operatingsystemrelease =~ /^(23|24|25).*/ ) {
                $ossec_service_provider = 'redhat'
                $api_service_provider = 'redhat'
                $wodle_openscap_content = {
                  'ssg-fedora-ds.xml' => {
                    'type' => 'xccdf',
                    profiles => ['xccdf_org.ssgproject.content_profile_standard', 'xccdf_org.ssgproject.content_profile_common',]
                  },
                }
              }
            }
            default: { fail('This ossec module has not been tested on your distribution') }
          }
        }
        default: { fail('This ossec module has not been tested on your distribution') }
      }
    }
    'windows': {
      $config_file = regsubst(sprintf('c:/Program Files (x86)/ossec-agent/ossec.conf'), '\\\\', '/')
      $shared_agent_config_file = regsubst(sprintf('c:/Program Files (x86)/ossec-agent/shared/agent.conf'), '\\\\', '/')
      $config_owner = 'Administrator'
      $config_group = 'Administrators'

      $manage_firewall = false

      $keys_file = regsubst(sprintf('c:/Program Files (x86)/ossec-agent/client.keys'), '\\\\', '/')
      $keys_mode = '0440'
      $keys_owner = 'Administrator'
      $keys_group = 'Administrators'

      $agent_service  = 'OssecSvc'
      $agent_package  = 'Wazuh Agent 3.10.2'
      $server_service = ''
      $server_package = ''
      $api_service = ''
      $api_package = ''
      $service_has_status  = true

      # TODO
      $validate_cmd_conf = undef
      # Pushed by shared agent config now
      $default_local_files =  [
        {'location' => 'Security' , 'log_format' => 'eventchannel',
        'query' => 'Event/System[EventID != 5145 and EventID != 5156 and EventID != 5447 and EventID != 4656 and EventID != 4658\
        and EventID != 4663 and EventID != 4660 and EventID != 4670 and EventID != 4690 and EventID!= 4703 and EventID != 4907]'},
        {'location' => 'System' , 'log_format' =>  'eventlog'  },
        {'location' => 'active-response\active-responses.log' , 'log_format' =>  'syslog'  },
      ]
    }
  default: { fail('This ossec module has not been tested on your distribution') }
  }
}
