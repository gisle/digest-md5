package Digest::SHA1;

# This only demonstrates the interface

$VERSION = '0.01';

use SHA 1.2;

my $sha_ver = SHA::sha_version();
die "Wrong SHA version ($sha_ver)" unless $sha_ver eq "SHA-1";

sub new {
    SHA->new;
}

1;
