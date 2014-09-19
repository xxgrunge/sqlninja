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

# property flags
use constant SESSION_PROPERTY_DBMS_VERSION => 'dbms_version';
use constant SESSION_PROPERTY_CURRENT_USER => 'system_user';
use constant SESSION_PROPERTY_CURRENT_USER_IS_ADMIN => 'system_user_is_admin';
use constant SESSION_PROPERTY_AUTH_MECHANISM => 'auth_mechanism';
use constant SESSION_PROPERTY_CURRENT_DATABASE => 'current_db';
use constant SESSION_PROPERTY_USER => 'user';
use constant SESSION_PROPERTY_USER_NUM => 'user_num';
use constant SESSION_PROPERTY_DATABASE_NUM => 'db_num';
use constant SESSION_PROPERTY_CLIENT_IP_ADDR => 'client_ip_addr';
use constant SESSION_PROPERTY_PASSWORD_HASH => 'password_hash';


use constant SESSION_PROPERTY_VERSION => 'session_version';
use constant SESSION_PROPERTY_LANGUAGE_MAP => 'language_map';
use constant SESSION_PROPERTY_LANGUAGE_MAP_FILE => 'language_map_file';
use constant SESSION_PROPERTY_LANGUAGE_MAP_WEIGHTS => 'language_map_weights';


my $db_h = undef;
my $session_id = undef;


# check if session is enabled
sub session_is_enabled {
	return $conf->{'store_session'};
}

sub session_is_active {
	if ($db_h == undef or $session_id == undef) {
		die("Womething went wrong with the session database\n");
	}

	return 1;
}

sub session_open {
	# if there is no explicit session file name specified in the config, we'll choose the default (session.db)
	if (!session_is_enabled()) {
		print "storing progress in session is disabled in config\n";
		return;
	}

	# load the db
	print_verbose("Loading session database: " . $conf->{'session_file'} . "\n");

	$db_h = DBI->connect("dbi:SQLite:dbname=" . $conf->{'session_file'}, "", "",  { RaiseError => 1 }, ) or die $DBI::errstr;

	# create schema if it didn't exist yet
	$db_h->do(
		"CREATE TABLE IF NOT EXISTS sessions (".
			"id INTEGER PRIMARY KEY AUTOINCREMENT,".
			"host TEXT,".
			"port INTEGER,".
			"url TEXT,".
			"created TEXT,".
			"UNIQUE (host, port) ON CONFLICT IGNORE".
		");"
	);
	$db_h->do(
		"CREATE TABLE IF NOT EXISTS properties (".
			"id INTEGER PRIMARY KEY AUTOINCREMENT,".
			"session_id INT,".
			"property TEXT,".
			"value TEXT,".
			"updated TEXT,".
			"UNIQUE (session_id, property, value) ON CONFLICT REPLACE".
		");"
	);
	$db_h->do(
		"CREATE TABLE IF NOT EXISTS databases (".
			"id INTEGER PRIMARY KEY AUTOINCREMENT,".
			"session_id INT,".
			"name TEXT,".
			"table_num INT,".
			"updated TEXT,".
			"UNIQUE (session_id, name) ON CONFLICT IGNORE".
		");"
	);
	$db_h->do(
		"CREATE TABLE IF NOT EXISTS tables (".
			"id INTEGER PRIMARY KEY AUTOINCREMENT,".
			"db_id INT,".
			"name TEXT,".
			"column_num INT,".
			"updated TEXT,".
			"UNIQUE (db_id, name) ON CONFLICT IGNORE".
		");"
	);
	$db_h->do(
	"CREATE TABLE IF NOT EXISTS columns (".
			"id INTEGER PRIMARY KEY AUTOINCREMENT,".
			"table_id INT,".
			"name TEXT,".
			"datatype TEXT,".
			"updated TEXT,".
			"UNIQUE (table_id, name) ON CONFLICT IGNORE".
		");"
	);
	
	# add version number if this is a new session file (we might need this in future for compatibility checks)
	$db_h->do(
	"INSERT OR IGNORE INTO properties (ID, session_id, property, value, updated) VALUES (0, NULL, '". SESSION_PROPERTY_VERSION ."','". $conf->{'RELEASE'} ."', NULL)"
	);

	print_verbose("Checking existing session for " . $conf->{host} . ":" . $conf->{port} . "\n");

	# getting or creating session
	my $stmt = $db_h->prepare("INSERT INTO sessions (host, port, url, created) VALUES (?, ?, ?, datetime('now','localtime'))");
	$stmt->execute($conf->{host}, $conf->{port}, $conf->{url});
	$stmt->finish();

	$stmt = $db_h->prepare("SELECT id, created FROM sessions WHERE host = ? and port = ? and url = ?");
	$stmt->execute($conf->{host}, $conf->{port}, $conf->{url});
	my ($session, $created) = $stmt->fetchrow();
	$stmt->finish();

	print_verbose("Using session '$session' which was created on $created\n");

	$session_id = $session;
}


# storing functions
sub session_store_property {
	my ($property, $value) = @_;

	if (!session_is_enabled() or !session_is_active()) {
		return;
	}

	my $query = "INSERT INTO properties (session_id, property, value, updated) VALUES (?, ?, ?, datetime('now','localtime'))";
	my $stmt = $db_h->prepare($query);
	$stmt->execute($session_id, $property, $value);
	$stmt->finish();

	print_verbose("storing property '$property' in session\n");
}

# store a single (unique) value. If a property by that name already exists, it will be overwritten
sub session_store_property_unique {
	my ($property, $value) = @_;

	if (!session_is_enabled() or !session_is_active()) {
		return;
	}

	my $query = "INSERT OR REPLACE INTO properties (session_id, id, property, value, updated) VALUES (?, (SELECT id FROM properties WHERE property = ? AND session_id = ?), ?, ?, datetime('now','localtime'))";
	my $stmt = $db_h->prepare($query);
	$stmt->execute($session_id, $property, $session_id, $property, $value);
	$stmt->finish();

	print_verbose("storing property '$property' in session\n");
}

sub session_store_database {
	my ($database) = @_;

	my $query = "INSERT INTO databases (session_id, name, updated) VALUES (?, ?, datetime('now','localtime'))";
	my $stmt = $db_h->prepare($query);
	$stmt->execute($session_id, $database);
	$stmt->finish();

	print_verbose("storing database '$database' in session\n");
}

sub session_store_table {
	my ($database, $table) = @_;

	my $query = "INSERT INTO tables (db_id, name, updated) VALUES ((SELECT MAX(id) FROM databases WHERE databases.name = ? AND session_id = ?), ?, datetime('now','localtime'))";
	my $stmt = $db_h->prepare($query);
	$stmt->execute($database, $session_id, $table);
	$stmt->finish();

	print_verbose("storing table '$table' in session\n");

}

sub session_store_column {
	my ($database, $table, $column, $datatype) = @_;

	my $query = "INSERT INTO columns (table_id, name, datatype, updated) VALUES ((SELECT MAX(t.id) FROM tables t JOIN databases d ON t.db_id = d.id WHERE d.name = ? AND d.session_id = ? AND t.name = ?), ?, ?, datetime('now','localtime'))";
	my $stmt = $db_h->prepare($query);
	$stmt->execute($database, $session_id, $table, $column, $datatype);
	$stmt->finish();

	print_verbose("storing column '$column' in session\n");
}


sub session_store_table_num {
	my ($database, $table_num) = @_;

	my $query = "UPDATE databases SET table_num = ? WHERE name = ? AND session_id = ?";
	my $stmt = $db_h->prepare($query);
	$stmt->execute($table_num, $database, $session_id);
	$stmt->finish();

	print_verbose("storing table number for '$database' in session\n");
}

sub session_store_column_num {
	my ($database, $table, $column_num) = @_;

	my $query = "UPDATE tables SET column_num = ? WHERE name = ? AND db_id = (SELECT max(id) FROM databases WHERE name = ? AND session_id = ?)";
	my $stmt = $db_h->prepare($query);
	$stmt->execute($column_num, $table, $database, $session_id);
	$stmt->finish();

	print_verbose("storing column number for '$database.$table' in session\n");
}

sub session_create_row_structure {
	my ($database, $table) = @_;

	my $table_name = "$session_id.$database.$table";

	my $all_columns = session_load_columns($database, $table);

	my $create_query = "CREATE TABLE IF NOT EXISTS ". $db_h->quote($table_name) ." (row_id INTEGER PRIMARY KEY, ";
	foreach my $column (@{$all_columns}) {
		$create_query .=  $db_h->quote("_" . @{$column}[0]) . " TEXT, ";
	}
	$create_query .= ' updated TEXT, UNIQUE (row_id) ON CONFLICT REPLACE)';

#	print "$create_query\n";
	$db_h->do($create_query);
}

sub session_store_row {
	my ($database, $table, $row_id, $columns, $row) = @_;

	my $table_name = "$session_id.$database.$table";
	
	# check if there's already a row
	my $query_select = "SELECT row_id FROM " . $db_h->quote($table_name) . " WHERE row_id = ?";
	my $stmt = $db_h->prepare($query_select);
	$stmt->execute($row_id);
	my $row_id_exists = $stmt->fetchrow();
	$stmt->finish();

	my $query_insert;
	if ($row_id_exists ne "") {

		# update row
		$query_insert = "UPDATE " . $db_h->quote($table_name) . " SET ";
		foreach my $column (@{$columns}) {
			$query_insert .= $db_h->quote('_' . $column) . '=?,';
		}
		$query_insert .= " updated = datetime('now','localtime') WHERE row_id = " . $row_id;

	} else {
		# insert new row
		$query_insert = "INSERT INTO " . $db_h->quote($table_name) . " (row_id,";
		foreach my $column (@{$columns}) {
			$query_insert .= $db_h->quote('_' . $column) . ',';
		}
		$query_insert .= 'updated) VALUES (' . $row_id . ', ';
	
		foreach my $column (@{$columns}) {
			$query_insert .= "? ,"
		}
		$query_insert .= "datetime('now','localtime'))";
	}

	$stmt = $db_h->prepare($query_insert);
	$stmt->execute(@{$row});
	$stmt->finish();

}

# loading functions
# $pattern is optional
sub session_load_property {
	my ($property, $pattern) = @_;

	if (!session_is_enabled() or !session_is_active()) {
		return ("","");
	}
	
	my $stmt;
	if ($pattern eq "") {
		$stmt = $db_h->prepare("SELECT value,updated FROM properties WHERE property = ?");
		$stmt->execute($property);
	} else {
		$stmt = $db_h->prepare("SELECT value,updated FROM properties WHERE property = ? AND value LIKE ?");
		$stmt->execute($property, $pattern);
		
	}

	my ($value, $updated) = $stmt->fetchrow();
	$stmt->finish();

	if ($value ne "") {
		print_verbose "loading property '$property' from session\n";
	}

	return ($value, $updated);
}

sub session_load_all_properties {
	my ($property) = @_;

	my @results;
	if (!session_is_enabled() or !session_is_active()) {
		return \@results;
	}
	
	my $stmt = $db_h->prepare("SELECT value FROM properties WHERE property = ?");
	$stmt->execute($property);
	my $props = $stmt->fetchall_arrayref();
	$stmt->finish();

	foreach my $prop (@{$props}) {
		push (@results, $prop->[0]);
	}

	print_verbose "loading properties '$property' from session\n";

	return \@results;
}

sub session_load_databases {

	my @result;

	if (!session_is_enabled() or !session_is_active()) {
		return \@result;
	}
	
	my $stmt = $db_h->prepare("SELECT name FROM databases WHERE session_id = ?");
	$stmt->execute($session_id);
	my $dbs = $stmt->fetchall_arrayref();
	$stmt->finish();

	foreach my $db (@{$dbs}) {
		push (@result, $db->[0]);
	}

	print_verbose "loading databases from session\n";

	return \@result;
}

sub session_load_tables {
	my ($database, $pattern) = @_;

	my @result;

	if (!session_is_enabled() or !session_is_active()) {
		return \@result;
	}

	if ($pattern eq "") {
		$pattern = "%";
	}
	
	my $stmt = $db_h->prepare("SELECT t.name FROM tables t JOIN databases d ON t.db_id = d.id WHERE d.session_id = ? AND d.name = ? AND t.name LIKE ?");
	$stmt->execute($session_id, $database, $pattern);
	my $tables = $stmt->fetchall_arrayref();
	$stmt->finish();

	foreach my $table (@{$tables}) {
		push (@result, $table->[0]);
	}

	print_verbose "loading tables from session\n";

	return \@result;
}

sub session_load_columns {
	my ($database, $table, $pattern) = @_;	

	my @result;

	if (!session_is_enabled() or !session_is_active()) {
		return \@result;
	}

	if ($pattern eq "") {
		$pattern = "%";
	}
	
	my $stmt = $db_h->prepare("SELECT c.name, c.datatype FROM (tables t JOIN databases d ON t.db_id = d.id) JOIN columns c ON c.table_id = t.id WHERE d.session_id = ? AND d.name = ? AND t.name = ? AND c.name LIKE ? order by c.id");
	$stmt->execute($session_id, $database, $table, $pattern);
	my $columns = $stmt->fetchall_arrayref();
	$stmt->finish();

	foreach my $column (@{$columns}) {
		my @c;
		push(@c, $column->[0]);
		push(@c, $column->[1]);
		push (@result, \@c);
	}

	print_verbose "loading columns from session\n";

	return \@result;
}

sub session_load_table_num {
	my ($database) = @_;

	my $query = "SELECT table_num FROM databases WHERE name = ? AND session_id = ?";
	my $stmt = $db_h->prepare($query);
	$stmt->execute($database, $session_id);
	my $value = $stmt->fetchrow();
	$stmt->finish();

	print_verbose("loading table number for '$database' from session\n");

	return $value;
}

sub session_load_column_num {
	my ($database, $table) = @_;

	my $query = "SELECT column_num FROM tables WHERE name = ? AND db_id = (SELECT max(id) FROM databases WHERE name = ? AND session_id = ?)";
	my $stmt = $db_h->prepare($query);
	$stmt->execute($table, $database, $session_id);
	my $value = $stmt->fetchrow();
	$stmt->finish();

	print_verbose("loading column number for '$database.$table' from session\n");

	return $value;
}



sub session_load_rows {
	my ($database, $table) = @_;

	my $table_name = "$session_id.$database.$table";

	my $columns = session_load_columns($database, $table);

	my $query_select = "SELECT row_id,";
	foreach my $column (@{$columns}) {
		my $column_name = @{$column}[0]; 
		$column_name =~ s/['\s"]//g;
		$query_select .= '_' . $column_name  . ',';
	}
	$query_select .= "updated FROM " . $db_h->quote($table_name);

	my $stmt = $db_h->prepare($query_select);
	$stmt->execute();
	my $rows = $stmt->fetchall_arrayref();
	$stmt->finish();
	

	my @result;
	foreach my $row (@{$rows}) {
		my @r;
		foreach my $field (@{$row}) {
			push(@r, $field);
		}
		push (@result, \@r);
	}


	return \@result;
}

sub session_print 
{
	print "\nPROPERTIES\n----------------------------------------\n";

	my ($dbms_version, $updated) = session_load_property(SESSION_PROPERTY_DBMS_VERSION);
	print "DBMS Version:       $dbms_version\n";
	my ($auth, $updated) = session_load_property(SESSION_PROPERTY_AUTH_MECHANISM) ;
	print "Auth Mechanism:     $auth\n";
	my ($current_db, $updated) = session_load_property(SESSION_PROPERTY_CURRENT_DATABASE) ;
	print "Current Database:   $current_db\n";
	my ($current_user, $updated) = session_load_property(SESSION_PROPERTY_CURRENT_USER) ;
	print "Current User:       $current_user\n";

	my ($users_num, $updated) = session_load_property(SESSION_PROPERTY_USER_NUM);
	my $users = session_load_all_properties(SESSION_PROPERTY_USER);

	print "Users: \n";
	for (my $u = 0; $u < $users_num; $u++) {
		if ($u < scalar @{$users}) {
			printf "  - %-20s " , @{$users}[$u];
			my ($hash, $updated) = session_load_property(SESSION_PROPERTY_PASSWORD_HASH . "_" . @{$users}[$u]);
			if ($hash ne "") {
				print "(hash: $hash)";
			}
		} else {
			print "  - {unknown}"; 
		}
		print "\n";
	}


	print "\nSCHEMA\n----------------------------------------\n";

	my ($db_num, $updated) = session_load_property(SESSION_PROPERTY_DATABASE_NUM);
	if ($db_num eq "") {
		my ($current_db, $updated) = session_load_property(SESSION_PROPERTY_CURRENT_DATABASE);
		if ($current_db ne "") {
			$db_num = 1;
			print "We only know the current database. There might be more...\n";
		}
	}
	my $dbs = session_load_databases();
	for (my $d = 0; $d < $db_num; $d++) {
		if ($d < scalar @{$dbs}) {
			print @{$dbs}[$d] . "  [Database]\n";
			
			my $table_num = session_load_table_num(@{$dbs}[$d]);
			if ($table_num ne "") {
				my $tables = session_load_tables(@{$dbs}[$d]);
				for (my $t = 0; $t < $table_num; $t++) {
					print "   |\n";
					if ($t < scalar(@{$tables})) {
						print "   +- ". @{$tables}[$t] ."  [Table]\n";

						my $column_num = session_load_column_num(@{$dbs}[$d], @{$tables}[$t]);
						if ($column_num ne "") {

							my $columns = session_load_columns(@{$dbs}[$d], @{$tables}[$t]);
							for (my $c = 0; $c < $column_num; $c++) {
								print "   |    |\n";
								if ($c < scalar(@{$columns})) {
								my $column = @{$columns}[$c];
									print "   |    +-" . @{$column}[0] . "  [" . @{$column}[1] . "]\n";
								} else {
									print "   |    +- {unknown}\n";
								}
							}
						}
					} else {
						print "   +- {unknown}\n";			
					}
				}
			}
		} else {
			print  "{unknown}  [Database]\n";
		}

		print "\n";

	}

}

sub session_refresh
{
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