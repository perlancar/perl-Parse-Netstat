package Parse::Netstat::freebsd;

use 5.010001;
use strict;
use warnings;

use Exporter;
our @ISA = qw(Exporter);
our @EXPORT_OK = qw(parse_netstat parse_netstat_win);

# VERSION

our %SPEC;

$SPEC{parse_netstat} = {
    v => 1.1,
    summary => 'Parse the output of FreeBSD "netstat" command',
    description => <<'_',

Netstat can be called with `-n` (show raw IP addresses and port numbers instead
of hostnames or port names) or without. It can be called with `-a` (show all
listening and non-listening socket) option or without.

Tested with FreeBSD 10.1's netstat.

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
        unix => {
            summary => 'Whether to parse Unix socket connections',
            schema  => [bool => default => 1],
        },
    },
};
sub parse_netstat {
    my %args = @_;
    my $output = $args{output} or return [400, "Please specify output"];
    my $tcp    = $args{tcp} // 1;
    my $udp    = $args{udp} // 1;
    my $unix   = $args{unix} // 1;

    my $in_unix;
    my $in_unix_header;
    my @conns;
    my $i = 0;
    for my $line (split /^/, $output) {
        $i++;
        my %k;
        if ($line =~ /^tcp/ && $tcp) {
            #Proto Recv-Q Send-Q Local Address               Foreign Address             State       PID/Program name
            #tcp4       0      0 192.168.1.33.632       192.168.1.10.2049      CLOSED
            $line =~ m!^(?P<proto>tcp[46]?) \s+ (?P<recvq>\d+) \s+ (?P<sendq>\d+)\s+
                       (?P<local_host>\S+?)[:.](?P<local_port>\w+)\s+
                       (?P<foreign_host>\S+?)[:.](?P<foreign_port>\w+|\*)\s+
                       (?P<state>\S+) (?: \s+ (?:
                               (?P<pid>\d+)/(?P<program>.+?) |
                               -
                       ))? \s*$!x
                           or return [400, "Can't parse tcp line (#$i): $line"];
            %k = %+;
        } elsif ($line =~ /^udp/ && $udp) {
            #Proto Recv-Q Send-Q Local Address          Foreign Address        (state)
            #udp4       0      0 *.879                  *.*
            $line =~ m!^(?P<proto>udp[46]?) \s+ (?P<recvq>\d+) \s+ (?P<sendq>\d+) \s+
                       (?P<local_host>\S+?)[:.](?P<local_port>\w+|\*)\s+
                       (?P<foreign_host>\S+?)[:.](?P<foreign_port>\w+|\*)
                       (?: \s+
                           (?P<state>\S+)?
                           (?: \s+ (?:
                                   (?P<pid>\d+)/(?P<program>.+?) |
                                   -
                           ))?
                       )? \s*$!x
                           or return [400, "Can't parse udp line (#$i): $line"];
            %k = %+;
        } elsif ($in_unix && $unix) {
            #Address  Type   Recv-Q Send-Q    Inode     Conn     Refs  Nextref Addr
            #fffffe00029912d0 stream      0      0 fffffe0002d8abd0        0        0        0 /tmp/ssh-zwZwlpzaip/agent.1089
            $line =~ m!^(?P<address>\S+) \s+ (?P<type>\S+) \s+
                       (?P<recvq>\d+) \s+ (?P<sendq>\d+) \s+ (?P<inode>[0-9a-f]+) \s+ (?P<conn>[0-9a-f]+) \s+
                       (?P<refs>[0-9a-f]+) \s+ (?P<nextref>[0-9a-f]+)
                       (?:
                           \s+
                           (?P<addr>.+)
                       )?
                       \s*$!x
                           or return [400, "Can't parse unix/freebsd line (#$i): $line"];
            %k = %+;
            $k{proto} = 'unix';
        } elsif ($in_unix_header) {
            $in_unix_header = 0;
            $in_unix++;
        } elsif ($line =~ /^Active UNIX domain sockets/) {
            $in_unix_header++;
        } else {
            next;
        }
        push @conns, \%k;
    }

    [200, "OK", {active_conns => \@conns}];
}

1;
# ABSTRACT: Parse the output of FreeBSD "netstat" command

=head1 SYNOPSIS

 use Parse::Netstat qw(parse_netstat);
 my $res = parse_netstat(output=>join("", `netstat -anp`), flavor=>"freebsd");

Sample `netstat -anp` output:

# EXAMPLE: share/netstat-samples/netstat-an-freebsd-10.1

Sample result:

# CODE: require Parse::Netstat::freebsd; Parse::Netstat::freebsd::parse_netstat(output => do { local $/; open my $fh, "<", "share/netstat-samples/netstat-an-freebsd-10.1" or die; ~~<$fh> });
