package Digest::HMAC;
$VERSION = "0.01";

use strict;

# OO interface

sub new
{
    my($class, $key, $hasher, $block_size) =  @_;
    $block_size ||= 64;
    $key = $hasher->new->add($key)->digest if length($key) > $block_size;

    my $self = bless {}, $class;
    $self->{k_ipad} = $key ^ (chr(0x36) x $block_size);
    $self->{k_opad} = $key ^ (chr(0x5c) x $block_size);
    $self->{hasher} = $hasher->new->add($self->{k_ipad});
    $self;
}

sub reset
{
    my $self = shift;
    $self->{hasher}->reset->add($self->{k_ipad});
    $self;
}

sub add     { shift->{hasher}->add(@_)     }
sub addfile { shift->{hasher}->addfile(@_) }

sub _digest
{
    my $self = shift;
    my $inner_digest = $self->{hasher}->digest;
    $self->{hasher}->reset->add($self->{k_opad}, $inner_digest);
}

sub digest    { shift->_digest->digest;    }
sub hexdigest { shift->_digest->hexdigest; }
sub b64digest { shift->_digest->b64digest; }


# Functional interface

require Exporter;
*import = \&Exporter::import;
use vars qw(@EXPORT_OK);
@EXPORT_OK = qw(hmac hmac_hex);

sub hmac
{
    my($data, $key, $hash_func, $block_size) = @_;
    $block_size ||= 64;
    $key = &$hash_func($key) if length($key) > $block_size;

    my $k_ipad = $key ^ (chr(0x36) x $block_size);
    my $k_opad = $key ^ (chr(0x5c) x $block_size);

    &$hash_func($k_opad, &$hash_func($k_ipad, $data));
}

sub hmac_hex { unpack("H*", &hmac); }

1;
