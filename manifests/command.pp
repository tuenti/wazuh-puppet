# Wazuh App Copyright (C) 2019 Wazuh Inc. (License GPLv2)
# Define an ossec command
define wazuh::command(
  $command_name,
  $command_executable,
  $command_extra_args,
  $command_expect = 'srcip',
  $command_timeout_allowed = 'yes',
) {
  require wazuh::params_manager

  concat::fragment { $name:
    target  => 'ossec.conf',
    order   => 46,
    content => template('wazuh/fragments/_command.erb'),
  }
}
