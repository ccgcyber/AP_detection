#!/usr/bin/perl

# (C) 2004

print qq!
Thanks for using wdetect.

The auto-update functionality is presently disabled.  Contact
your support representative for specific information regarding
this functionality.

!;

exit(0);

$file = "wdetect.new";
$url = "http:// /wdetect";

$comm = "/usr/bin/wget -q --tries=1 -O $file $url";

$get = `$comm`;

print "New wdetect binary has been saved to file wdetect.new\n";
print "Ensure that the file is not corrupted and then run\n";
print "mv wdetect.new wdetect\n";

exit(0);


