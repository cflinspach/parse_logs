# parse_logs.pl
Check plugin for Icinga2 that parses logs and counts the occurrences of a string. Also collects and displays logs from IcingaWeb2



Currently only works with Cisco devices but more to come.

# Installation
Requires Net::Telnet, Net::Telnet::Cisco, Net::Telnet::Cisco, File::ReadBackwards
You can change the directory logs are stored in by editing line 26 (`my $fileDir = '/var/www/html/parse_logs/';`)

```
Usage:

check_logs.pl -H [host] -U [username] -P [password] -T [type] -s [search] -w [warn] -c [crit]


Possible Types:
Cisco
```

The check command defintion for Icinga2 is:
```
object CheckCommand "parse_logs" {
    import "plugin-check-command"
    command = [
        "/usr/bin/sudo",
        "/usr/lib/nagios/plugins/parse_logs.pl"
    ]
    arguments += {
        "-H" = "$address$"
        "-P" = "$logs_password$"
        "-T" = "$logs_device_type$"
        "-U" = "$logs_username$"
        "-c" = "$logs_crit$"
        "-s" = "$logs_search_string$"
        "-w" = "$logs_warn$"
    }
}
```


# Usage in IcingaWeb2
We use the action URL in IcingaWeb2 to display the logs. 



