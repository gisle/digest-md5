package Digest::HMAC;

use strict;

sub new
{
    my($class, $key, $hasher, $block_size) =  @_;
    $key = $hasher->new->add($key)->digest if length($key) > $block_size;
    $block_size ||= 64;

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

sub _digest
{
    my $self = shift;
    my $inner_digest = $self->{hasher}->digest;
    $self->{hasher}->reset->add($self->{k_opad}, $inner_digest);
}

sub digest    { shift->_digest->digest;    }
sub hexdigest { shift->_digest->hexdigest; }
sub b64digest { shift->_digest->b64digest; }

1;
