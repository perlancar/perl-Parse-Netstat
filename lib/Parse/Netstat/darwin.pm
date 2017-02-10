package Parse::Netstat::darwin;

# DATE
# VERSION

use 5.010001;
use strict;
use warnings;

use Exporter;
our @ISA = qw(Exporter);
our @EXPORT_OK = qw(parse_netstat);

our %SPEC;

require Parse::Netstat::freebsd;

$SPEC{parse_netstat} = do {
    my $meta = { %{ $Parse::Netstat::freebsd::SPEC{parse_netstat} } };
    $meta->{summary} = 'Parse the output of Mac OS X "netstat" command',
    $meta->{description} = <<'_';

Netstat can be called with `-n` (show raw IP addresses and port numbers instead
of hostnames or port names) or without. It can be called with `-a` (show all
listening and non-listening socket) option or without.

_
    $meta;
};
sub parse_netstat {
    Parse::Netstat::freebsd::parse_netstat(@_);
}
1;
# ABSTRACT:

=head1 SYNOPSIS

 use Parse::Netstat qw(parse_netstat);
 my $res = parse_netstat(output=>join("", `netstat -an`), flavor=>"darwin");

Sample `netstat -an` output:

# EXAMPLE: share/netstat-samples/netstat-an-darwin

Sample result:

# CODE: require Parse::Netstat::darwin; Parse::Netstat::darwin::parse_netstat(output => do { local $/; open my $fh, "<", "share/netstat-samples/netstat-an-darwin" or die; ~~<$fh> });
