#!/usr/bin/env perl

use v5.10;

use autodie;
use strict;
use warnings;

use Crypt::Cipher::AES;
use JSON ();
use MIME::Base64;
use HTML::Tiny;

use constant KEY => 'hdfzpysvpzimorhk';

my @site = ();
for my $file (@ARGV) {
  open my $fh, '<', $file;
  while (<$fh>) {
    next unless /^(\w+),(.*)/;
    my ( $key, $val ) = ( $1, $2 );
    push @site, {} if $key eq "Name";
    $val = decrypt($val) if $key eq "PW";
    my $stash = $site[-1];
    $stash->{$key} = $val;
  }
}

say '<?xml version="1.0" encoding="UTF-8"?>';
my $h = HTML::Tiny->new;
say $h->tag(
  FileZilla3 => { platform => "mac", version => "3.27.0.1" },
  $h->tag( Servers => [map { make_server($_) } @site] )
);

sub decrypt {
  my $pw  = shift;
  my $enc = pack 'H*', $pw;
  my $cc  = Crypt::Cipher::AES->new(KEY);
  my $dec = $cc->decrypt($enc);
  $dec =~ s/[\x00-\x1f].*//g;
  return $dec;
}

sub make_server {
  my $rec = shift;
  my $h   = HTML::Tiny->new;
  return $h->tag(
    Server => [
      $h->tag( Host     => $rec->{Host} ),
      $h->tag( Port     => $rec->{Port} ),
      $h->tag( Protocol => 0 ),
      $h->tag( Type     => 0 ),
      $h->tag( User     => $rec->{User} ),
      $h->tag(
        Pass => { encoding => "base64" },
        encode_base64( $rec->{PW}, '' )
      ),
      $h->tag( Logontype                  => 1 ),
      $h->tag( TimezoneOffset             => 0 ),
      $h->tag( PasvMode                   => 'MODE_DEFAULT' ),
      $h->tag( MaximumMultipleConnections => 0 ),
      $h->tag( EncodingType               => 'Auto' ),
      $h->tag( BypassProxy                => 0 ),
      $h->tag( Name                       => $rec->{Name} ),
      $h->tag('Comments'),
      $h->tag( LocalDir            => $rec->{PthL} ),
      $h->tag( RemoteDir           => $rec->{PthR} ),
      $h->tag( SyncBrowsing        => 0 ),
      $h->tag( DirectoryComparison => 0 ),
    ]
  );
}

# vim:ts=2:sw=2:sts=2:et:ft=perl
