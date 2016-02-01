use Digest::MD5;
use Test::More tests => 6;

$^W = 0; # No warnings
my $stdr = "";
{
  local *STDERR;
  open STDERR, '>', \$stdr;
  $str = Digest::MD5->md5_hex("foo");
  is($stdr,'','No warnings');
}

$stdr = "";
{
  $^W = 1; # magic turn on warnings
  local *STDERR;
  open STDERR, '>', \$stdr;
  $str = Digest::MD5->md5_hex("foo");
  like($stdr,qr/Digest::MD5::md5_hex function probably called as class method/,
        'Lexical warning passed to XSUB');
}

$stdr = "";
{
  $^W = 0; # No warnings
  local *STDERR;
  open STDERR, '>', \$stdr;
  $str = Digest::MD5->md5_hex("foo");
  is($stdr,'','No warnings again');
}

$stdr = "";
{
  use warnings;
  local *STDERR;
  open STDERR, '>', \$stdr;
  $str = Digest::MD5->md5_hex("foo");
  like($stdr,qr/Digest::MD5::md5_hex function probably called as class method/,
        'use warnings passed to XSUB');
}

$stdr = "";
{
  use strict;
  $^W = 0; # No warnings
  local *STDERR;
  open STDERR, '>', \$stdr;
  my $str = Digest::MD5->md5_hex("foo");
  is($stdr,'','No warnings and strict');
}

$stdr = "";
{
  use strict;
  use warnings;
  local *STDERR;
  open STDERR, '>', \$stdr;
  my $str = Digest::MD5->md5_hex("foo");
  like($stdr,qr/Digest::MD5::md5_hex function probably called as class method/,
        'use warnings passed to XSUB while use strict');
}

