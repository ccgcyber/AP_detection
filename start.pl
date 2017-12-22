#!/usr/bin/perl
# $Version: $1.0.11$ 

$|=1;

$DEBUG = 0;

$conffile = "wdetect.conf";

# Do *not* change the value below unless you are ready to potentially
# DoS your own machine!  64 is a good number.  On average, you will complete 
# a full Class C network in less than 20 seconds.

#print_copyright();

$THREAD_COUNT = 32;               

die "Invalid THREAD_COUNT\n" if ($THREAD_COUNT > 255);

open (IN, "$conffile") || die YewSage();

$SIG{CHLD} = \&REAPER;

$SIG {'INT'} = \&cntrl_c_handler;

$report_format = shift;
if (lc($report_format) eq "html")
{
	$HTML = 1;
	html_headers();
}
else
{
	$HTML = 0;
}

$networkinit = 0;
while (<IN>) 
{
	$fchar = get_first_char($_);
	next if ($fchar =~ /\#|NO ENTRY/);
	if ($_ =~ /^network/)
	{
		$networkinit = 1;
		$_ =~ /.*\: ([0-9]+\.)([0-9]+\.)([0-9]+\.)([0-9]+)(\s+|)-(\s+|)([0-9]+\.)([0-9]+\.)([0-9]+\.)([0-9]+)/;
		$val[0] = $1; $val[1] = $2; $val[2] = $3; $val[3] = $4;
		$val[4] = $7; $val[5] = $8; $val[6] = $9; $val[7] = $10;
		$endingip = $7 . $8 . $9 . $10;
		for ($i=0;$i<8;$i++) {$val[$i] =~ s/\.//;}
		YewSage() if ( ($val[0] != $val[4]) || ($val[1] != $val[5]) );
		$isclean = sanitize();
		if ($isclean eq "ERROR")
		{
			print "Error with configuration file semantics\n";
			exit(0);
		}
		$init = $val[0] . "." . $val[1];
		for ($i=$val[2]; $i <= $val[6]; $i++)
		{
		    for ($j=0; $j<256; $j++)
		    {
			if ($pid = fork())
			{
				# parent
				if ($DEBUG)
				{
					print "Pushed $$ on pidzrray\n";
				}

				push (@pidzrray, $$);

				if ( ($j % $THREAD_COUNT) == ($THREAD_COUNT - 1) )
				{
					if ($DEBUG)
					{
						$pidzcount = `ps auxww \| grep -c start.pl`;
						print "$pidzcount current running processes\n";
						print "Parent is sleeping for 5 seconds\n";
					}
					sleep(5);                
				}
				html_end() if ( ($HTML == 1) && ($i == $val[6]) && ($j == 256) );
			}
			else
			{
                                # child
                                $command = "./wdetect " . $init . "." . $i . "." . $j;
                                if ($DEBUG)
                                {
                                        print "Child PID is $pid\n";
                                        print "running $command\n";
                                }

                                $rep = `$command`;
                                if ($rep =~ /Access/)
                                {
                                        @tmp = split(/\n/,$rep);
                                        $rep = $tmp[0];
                                        if ($HTML == 0)
                                        {
                                                print "$rep\n";
                                        }
                                        else
                                        {
                                                ($ip,$gen,$desc,$foundport,$uidpass) = split(/\:/,$rep);
                                                $desc =~ s/\n//;
                                                print_row($ip,$desc,$foundport,$uidpass); #f00                               
                                        }
                                }
                                html_end() if ( ($HTML == 1) && ($i == $val[6]) && ($j == 256) );
                                exit(0);
                        }

		    }
		}
	}

}	

if ($networkinit == 0)
{
	print "No valid \"network\" entries were found in the configuration file\n";
	print "wdetect did *not* scan any networks\n";
	exit(0);
}




sub get_first_char
{
	my $line = shift;
	my @rray = split(//,$line);
	my $cchar;
	foreach $cchar (@rray)
	{
		return ($cchar) if ($cchar ne '');
	}
	return ("NO ENTRY");
}




sub sanitize {
	foreach $tmp (@val)
	{
		return ("ERROR") if ($tmp !~ /[0-9]/);
		return ("ERROR") if ($tmp < 0);
		return ("ERROR") if ($tmp > 255);
	}
}
		



sub YewSage
{
	print qq!
Usage: Run start.pl from the same directory that has 
wdetect.conf.  Within wdetect.conf, you will have lines
that begin with "network : ".  An example configuration
might be something like:
network : 10.10.10.1-10.10.10.254

NOTE: no more than 1 class B network per 'network' declaration.
If you have multiple class B networks, then split them up in 
the wdetect.conf file
!;

	exit(0);
}



sub cntrl_c_handler 
{
    print "You should use a commandline kill -TERM to end these\n";
    print "processes.  We will attempt to gracefully shut down\n";
    # give children time to complete
    sleep(12);
    exit(0);                                      
}



sub REAPER
{
    1 until (-1 == waitpid(-1, WNOHANG));
    $SIG{CHLD} = \&REAPER;
}


sub print_copyright
{
print qq!
wdetect -- wireless AP detection tool
Copyright (C) 2004 
!;
}












sub html_headers
{
print qq!

<HTML><HEAD></HEAD><BODY BGCOLOR="FFFFFF"><TABLE WIDTH=100%><TR><TD><FONT SIZE=5 FACE="Times New Roman"><B>
NetTekSecure Wdetect</B></FONT></TD><TD>
<TABLE ALIGN=RIGHT BORDER=1><TR><TD><B>
$date<B></TD></TR></TABLE></TD></TR><TR><TD><FONT SIZE=3 FACE="Times New Roman"><B>Vulnerable network addresses
</B></FONT></TD></TR></TABLE><BR>
<TABLE WIDTH=100\% BORDER=1>
<TR>
    <TD><TABLE WIDTH=100\%>
    <TR><TD><B>Session name:</B>   Network Wireless Access Point Assessment Report  </TD>
</TR><TD></TD>
<TR><TD><TR><TD>
!;

}




sub html_end
{
print qq!


</table>
<TR><TD>
</BODY></HTML>
!;
}



sub print_row
{
my $lip = shift;        # IP
my $rep = shift;        # description
my $fport = shift;      # port it was found on
my $up = shift;         # userID/password used to log into machine
($uid,$passw) = split(/\|/,$up);
print qq!

<TR><TD><TR><TD>
<TABLE WIDTH=100\%>
<TR>
<TD width=30\%><a href="http://$lip">$lip</TD><TD width=30\%>$rep</TD>
<TD width=10\%>$fport</TD><TD width=30\%>$uid  $passw</TD>
</TR>
</TABLE>
!;
}

