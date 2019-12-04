# Wazuh App Copyright (C) 2019 Wazuh Inc. (License GPLv2)
# Define an email alert
define wazuh::email_alert(
  String                  $alert_email,
  Optional[Array[String]] $alert_group = undef,
  Enum['full', 'sms']     $alert_format = 'full',
  Optional[String]        $alert_location = undef,
  Boolean                 $alert_do_not_delay = false,
  Boolean                 $alert_do_not_group = false,
) {
  require wazuh::params_manager

  concat::fragment { $name:
    target  => 'ossec.conf',
    order   => 66,
    content => template('wazuh/fragments/_email_alert.erb'),
  }
}
