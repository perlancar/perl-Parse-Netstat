package Parse::Netstat::win32;

# DATE
# VERSION

use 5.010001;
use strict;
use warnings;

use Exporter;
our @ISA = qw(Exporter);
our @EXPORT_OK = qw(parse_netstat);

our %SPEC;

$SPEC{parse_netstat} = {
    v => 1.1,
    summary => 'Parse the output of Windows "netstat" command',
    description => <<'_',

Netstat can be called with `-n` (show raw IP addresses and port numbers instead
of hostnames or port names) or without. It can be called with `-a` (show all
listening and non-listening socket) option or without. And can be called with
`-p` (show PID/program names) or without.

_
    args => {
        output => {
            summary => 'Output of netstat command',
            schema => 'str*',
            req => 1,
        },
        tcp => {
            summary => 'Whether to parse TCP (and TCP6) connections',
            schema  => [bool => default => 1],
        },
        udp => {
            summary => 'Whether to parse UDP (and UDP6) connections',
            schema  => [bool => default => 1],
        },
    },
};
sub parse_netstat {
    my %args = @_;
    my $output = $args{output} or return [400, "Please specify output"];
    my $tcp    = $args{tcp} // 1;
    my $udp    = $args{udp} // 1;

    my @conns;
    my $i = 0;
    my $cur; # whether we're currently parsing TCP or UDP entry
    my $k;
    for my $line (split /^/, $output) {
        $i++;
        if ($line =~ /^\s*TCP\s/ && $tcp) {
            #  Proto  Local Address          Foreign Address        State           PID
            #  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       988
            #  c:\windows\system32\WS2_32.dll
            #  C:\WINDOWS\system32\RPCRT4.dll
            #  c:\windows\system32\rpcss.dll
            #  C:\WINDOWS\system32\svchost.exe
            #  -- unknown component(s) --
            #  [svchost.exe]
            #
            $line =~ m!^\s*(?P<proto>TCP6?) \s+
                       (?P<local_host>\S+?):(?P<local_port>\w+)\s+
                       (?P<foreign_host>\S+?):(?P<foreign_port>\w+|\*)\s+
                       (?P<state>\S+) (?: \s+ (?:
                               (?P<pid>\d+)
                       ))? \s*$!x
                           or return [400, "Can't parse tcp line (#$i): $line"];
            $k = { %+ };
            $cur = 'tcp';
            for ($k->{proto}) { $_ = lc }
            push @conns, $k;
        } elsif ($line =~ /^\s*UDP\s/ && $udp) {
            #  UDP    0.0.0.0:500            *:*                                    696
            #  [lsass.exe]
            #
            # XXX state not yet parsed
            $line =~ m!^\s*(?P<proto>UDP6?) \s+
                       (?P<local_host>\S+?):(?P<local_port>\w+)\s+
                       (?P<foreign_host>\S+?):(?P<foreign_port>\w+|\*)\s+
                       (?: \s+ (?:
                               (?P<pid>\d+)
                       ))? \s*$!x
                           or return [400, "Can't parse udp line (#$i): $line"];
            $k = { %+ };
            $cur = 'udp';
            for ($k->{proto}) { $_ = lc }
            push @conns, $k;
        } elsif ($cur) {
            $k->{execs} //= [];
            next if $line =~ /^\s*--/; # e.g. -- unknown component(s) --
            next if $line =~ /^\s*can not/i; # e.g.  Can not obtain ownership information
            push @{ $k->{execs} }, $1 if $line =~ /^\s*(\S.*?)\s*$/;
            next;
        } else {
            # a blank line or headers. ignore.
        }
    }

    [200, "OK", {active_conns => \@conns}];
}

1;
# ABSTRACT: Parse the output of Windows "netstat" command

=head1 SYNOPSIS

 use Parse::Netstat qw(parse_netstat);
 my $res = parse_netstat(output=>join("", `netstat -anp`), flavor=>"win32");

Sample `netstat -anp` output:

# EXAMPLE: share/netstat-samples/netstat-anp-win32

Sample result:

# CODE: require Parse::Netstat::win32; Parse::Netstat::win32::parse_netstat(output => do { local $/; open my $fh, "<", "share/netstat-samples/netstat-anp-win32" or die; ~~<$fh> });
