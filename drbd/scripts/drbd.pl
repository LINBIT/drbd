#!/usr/bin/perl -w

use strict;
use English;
use Sys::Hostname;

my @get_token_line;
my $token_line=0;
my $pname;
my %conf;

sub get_token()
  {
    my $token;
    if($#get_token_line < 0) {
      while(<CONFIG>) {
	$token_line++;
	chomp;                  # no newline
	s/\#.*//;               # no comments
	s/^\s+//;               # no leading white
	s/\s+$//;               # no trailing white
	next unless length;     # anything left?
	if( m/=/ ) { return $_; }
	else       { @get_token_line=split(/ /,$_); }
	return shift @get_token_line;
      }
    }
    $token=shift @get_token_line;
    if($token) { return $token; }
    return undef;
  }

sub open_section()
  {
    my $token=get_token();
    if($token ne "{") {
      die "$pname: expected { found $token in line $token_line";
    }
  }

sub skip_section()
  {
    my ($token,$dept);
    while($token=get_token())
      {
	if($token eq "{") { $dept++; }
	if($token eq "}") { $dept--; }
	if($dept == 0) { return; }
      }
  }

sub read_host_section($)
{
  my $conf=shift;
  my ($token,$name,$val);
  my %valid=("device" => "n",
	     "disk" => "n",
	     "address" => "n",
	     "port" => "n",
	    );

  open_section();

  while($token=get_token()) {
    if( $token =~ /=/ ) {
      ($name,$val)=split(/=/,$_);
      if($valid{$name} eq "n") {
	$valid{$name}="d";
	$$conf{$name}=$val;
	next;
      } else { die "$pname: unexpected token $token in line $token_line";}
    }
    if( $token eq "}") {
      foreach $name (keys %valid) {
	if($valid{$name} eq "n") {
	  die "$pname: $name not defined in line $token_line";
	}
      }
      return;
    }
    die "$pname: unexpected token $token in line $token_line";
  }
}

sub read_option_section($)
{
  my $conf=shift;
  my ($token,$val);

  open_section();

  while($token=get_token()) {
	if($token eq "}") { return; }
	if( $token =~ /=/ ) {
	  ($token,$val)=split(/=/,$_);
	  $$conf{$token}=$val;
	} else {
	  $$conf{$token}="";
	}
    }
}

sub read_resource_sec($)
{
    my $conf=shift;
    my ($token,$name);
    my %this;

    $name=get_token();
    $$conf{$name}=\%this;

    open_section();

    while($token=get_token()) {
      if($token eq "disk" || $token eq "net") {
	  read_option_section($this{$token}={});
	  next;
      }
      if($token eq "on") {
	$name=get_token();
	if($name eq hostname()) {
	  read_host_section($this{"self"}={});
	} else {
	  read_host_section($this{"other"}={});
	}
	next;
      }
      if( $token =~ /^protocol=(.*)/ ) { next;}
      if( $token =~ /^fsckcmd=(.*)/ ) { next;}
      if($token eq "}") {
	#TODO: ensure that here was protocol and fsckcmd
	return;
      }
      die "$pname: unexpected token $token in line $token_line";
    }
  }

sub read_config()
{
    my $token;

    open (CONFIG,"<drbd.conf")
	or die "can not open config file";

    while($token=get_token()) {
      if($token eq "resource") { read_resource_sec(\%conf); next; }
      die "$pname: unexpected token $token in line $token_line";
    }

    close CONFIG;
}


$pname=$0;
read_config();



