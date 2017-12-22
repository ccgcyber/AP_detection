#!/usr/bin/perl

print "Stopping wdetect\n";

@pidzrray = split(/\n/, `ps auxww \| egrep "wdetect|start.pl" \|grep -v grep`);

foreach $pidline (@pidzrray) 
{
	($owner,$pid,$junk) = split(/\s+/,$pidline);
	kill ('TERM', $pid);
	kill (9, $pid);
}

