#!/usr/bin/env perl

use v5.10;

use autodie;
use strict;
use warnings;

use Crypt::Cipher::AES;
use JSON ();
use MIME::Base64;
use Path::Class;

use constant KEY    => 'hdfzpysvpzimorhk';    # Yup!
use constant OUTDIR => "ftpconfig";

my @site = ();
for my $file (@ARGV) {
  open my $fh, '<', $file;
  while (<$fh>) {
    next unless /^(\w+),(.*)/;
    my ( $key, $val ) = ( $1, $2 );
    push @site, {} if $key eq "Name";
    next unless @site;
    $val = decrypt($val) if $key eq "PW";
    my $stash = $site[-1];
    $stash->{$key} = $val;
  }
}

for my $site (@site) {
  my $conf = file OUTDIR, $site->{Name} . ".json";
  say "$conf";
  $conf->parent->mkpath;
  save_json( $conf, make_server($site) );
}

sub save_json {
  my ( $file, $json ) = @_;
  my $fh = file($file)->openw;
  $fh->binmode(":utf8");
  $fh->print( JSON->new->pretty->canonical->encode($json) );
}

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
  return {
    host          => $rec->{Host},
    pass          => $rec->{PW},
    port          => $rec->{Port},
    promptForPass => JSON::false,
    protocol      => "ftp",
    remote        => $rec->{PthR},
    user          => $rec->{User},
  };
}

# vim:ts=2:sw=2:sts=2:et:ft=perl
