package Digest::HMAC_MD5;

# Contributed by Graham Barr <gbarr@ti.com>

use Digest::MD5 ();
use Exporter;
@ISA = qw(Digest::MD5);
@EXPORT_OK = qw(hmac_md5_digest hmac_md5_hexdigest);

sub _doit {
  my ($string,$key) = @_;

  if (length($key) > 64) { # need to reset key if too big
    my($md5) = new Digest::MD5;
    $md5->add($key);
    $key = $md5->digest;
  }

  # XOR the password with ipad & opad

  my $k_ipad = $key ^ (chr(0x36) x 64);
  my $k_opad = $key ^ (chr(0x5c) x 64);

  # perform inner MD5
  my $md5 = Digest::MD5->new($k_ipad,$string);

  # perform outer MD5
  return $md5->new($k_opad,$md5->digest);
}

sub hmac_md5_digest {
  &_doit->digest;
}

sub hmac_md5_hexdigest {
  &_doit->hexdigest;
}

1;
