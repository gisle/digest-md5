
eval {
   require Digest::SHA1;
};
if ($@) {
   print "1..0\n\n$@\n";
   exit;
}

print "1..3\n";

print "not " unless Digest::SHA1->new->add("abc")->hexdigest eq "a9993e364706816aba3e25717850c26c9cd0d89d";
print "ok 1\n";

Digest::SHA1->import(qw(sha1 sha1_hex sha1_base64));

print "not " unless sha1("abc") eq pack("H*", "a9993e364706816aba3e25717850c26c9cd0d89d");
print "ok 2\n";

print "not " unless sha1_hex("abc") eq "a9993e364706816aba3e25717850c26c9cd0d89d";
print "ok 3\n";

