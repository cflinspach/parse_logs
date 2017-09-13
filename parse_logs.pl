#!/usr/bin/perl
# About: Check plugin for Icinga2 to parse a network device's logs.
#
# 
# Version: 0.02
#
# Author: Casey Flinspach
#         cflinspach@protonmail.com
#
##########################################################################
use strict;
use warnings;
use POSIX qw(strftime);
use Getopt::Long qw(:config no_ignore_case);
use IO::Socket;
use Net::Telnet;
use Net::Telnet::Cisco;
use Net::OpenSSH;
use File::ReadBackwards;

my $search_string = '';
my $host = '';
my $username = '';
my $password = '';
my $device_type = '';
my $fileDir = '/var/www/html/parse_logs/';

my $crit = '';
my $warn = '';
my $result = 0;

GetOptions(
        "help|h-" => \my $help,
        "host|H=s" => \$host,
        "username|U=s" => \$username,
        "password|P=s" => \$password,
        "crit|c:s" => \$crit,
        "warn|w:s" => \$warn,
        "type|T=s" => \$device_type,
        "search|s=s" => \$search_string);
        
if($help || !$host) {
        help();
        exit;
}

sub help { print "check_logs v0.01
Usage:\n
check_logs.pl -H [host] -U [username] -P [password] -T [type] -s [search] -w [warn] -c [crit]\n

Possible Types:
Cisco\n
Extreme\n";
}

my $file = $fileDir . $host;
open my $stdout_fh, '>', $file or die;


# Cisco
if ($device_type =~ 'cisco' || $device_type =~ 'Cisco') {
	# Check for Telnet or SSH
	my $socket = IO::Socket::INET->new(PeerAddr => $host , PeerPort => 22 , Proto => 'tcp' , Timeout => 1);
	my $cisco_cmd = 'sh log ';	
	
	# SSH
	if ($socket) {
		my $ssh = Net::OpenSSH->new($host, user=>$username, 
                                           password=>$password, 
                                           timeout => 30, 
                                           master_stdout_fh => $stdout_fh,
                                           master_stderr_fh => $stdout_fh,
                                           master_opts => [-o => "KexAlgorithms=+diffie-hellman-group1-sha1",
                                                           -o => "HostKeyAlgorithms=+ssh-dss",
                                                           -o => "StrictHostKeyChecking no"]);
						             
		if ($ssh->error) {
			print "Unknown - Unable to connect to remote host: ". $ssh->error . "\n";
			exit 3;
		}
		
		# Cisco SSH command
		my $ssh_session = $ssh->system({stdout_fh=> $stdout_fh}, $cisco_cmd);
	}
	
	# Telnet
	if (!$socket) {
		my $telnet = Net::Telnet::Cisco->new(Host=> $host);
		$telnet->login($username, $password);
		print $stdout_fh $telnet->cmd($cisco_cmd);
	
	}
	
	# Open the log file and only read in the last five lines
	my $bak = File::ReadBackwards->new($file) or
		die "can't read file: $!\n";
	
	my @last_five_lines;
	while ( defined($_ = $bak->readline() ) && @last_five_lines < 5) {
		push @last_five_lines, $_;
	}

	# Count the occurences of the search string
	my %count;
	while (my $line = <@last_five_lines>) {
    	chomp $line;
    	foreach my $str ($line =~ /$search_string/g) {
    		$count{$str}++;
    	}
	}
	foreach my $str (sort keys %count) {
    	$result = $count{$str};
	}
	
};

# Extreme Networks
if ($device_type =~ 'extreme' || $device_type =~ 'Extreme') {
	# Check for Telnet or SSH
	my $socket = IO::Socket::INET->new(PeerAddr => $host , PeerPort => 23 , Proto => 'tcp' , Timeout => 1);
	my $extreme_cmd = 'sh log';
	
	# Telenet 
	if ($socket) {
		my $telnet = new Net::Telnet(Timeout=>5, Errmode=>'die', Prompt=>'/#/i');
		$telnet->open(Host=>$host);
		$telnet->login($username, $password);
		$telnet->cmd('disable clipaging');
		my @output = $telnet->cmd($extreme_cmd);
		$telnet->cmd('enable clipaging');
		print $stdout_fh @output;
		$telnet->close();
		
	}
	
	# SSH
	if (!$socket) {
		my $ssh = Net::OpenSSH->new($host, user=>$username, 
                                           password=>$password, 
                                           timeout => 30, 
                                           master_stdout_fh => $stdout_fh,
                                           master_stderr_fh => $stdout_fh,
                                           master_opts => [-o => "KexAlgorithms=+diffie-hellman-group1-sha1",
                                                           -o => "HostKeyAlgorithms=+ssh-dss",
                                                           -o => "StrictHostKeyChecking no"]);
						             
		$ssh->error and die "Unknown - Unable to connect to remote host: ". $ssh->error;

		# Cisco SSH command
		my $ssh_session = $ssh->system({stdout_fh=> $stdout_fh}, $extreme_cmd);
	}
	
	# Open the log file and only read in the first five lines
    open my $logfile, $file or die "Could not open $stdout_fh: $!";	


	# Count the occurences of the search string
	my %count;
	while (my $line = <$logfile>) {
    	foreach my $str ($line =~ /$search_string/g) {
    		$count{$str}++;
    	}
    	last if $. == 10;
	}
	close $logfile;
	
	foreach my $str (sort keys %count) {
    	$result = $count{$str};
	}

};


print "Counted $search_string: $result times\n";
if ($result < $warn) {
        print "OK - $search_string: $result \n";
        exit 0;
        } elsif ($result >= $warn && $result < $crit ) {
        print "WARNING - Dectected - $search_string: $result\n";
        exit 1;
        } elsif ($result >= $crit) {
        print "CRITICAL - Dectected - $search_string: $result\n";
        exit 2;
        } else {
        print "UNKNOWN \n";
        exit 3;
        }
