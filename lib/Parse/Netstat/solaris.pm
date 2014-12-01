package Parse::Netstat::solaris;

use 5.010001;
use strict;
use warnings;

use Exporter;
our @ISA = qw(Exporter);
our @EXPORT_OK = qw(parse_netstat);

# VERSION

our %SPEC;

$SPEC{parse_netstat} = {
    v => 1.1,
    summary => 'Parse the output of Solaris "netstat" command',
    description => <<'_',

Netstat can be called with `-n` (show raw IP addresses and port numbers instead
of hostnames or port names) or without. It can be called with `-a` (show all
listening and non-listening socket) option or without.

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

    my $proto = '';
    my @conns;
    my $i = 0;
    for my $line (split /^/, $output) {
        $i++;
        my %k;
        if ($line =~ /^UDP: IPv([46])/) {
            $proto = "udp$1";
        } elsif ($line =~ /^TCP: IPv([46])/) {
            $proto = "tcp$1";
        } elsif ($line =~ /^Active UNIX domain sockets/) {
            $proto = "unix";
        } elsif ($proto =~ /udp/ && $udp) {
            #UDP: IPv4
            #   Local Address        Remote Address      State
            #-------------------- -------------------- ----------
            #8.8.17.4.15934   8.8.7.7.53       Connected
            $line =~ /^\s*$/ and next; # blank line
            $line =~ /^\s+/ and next; # header
            $line =~ /^[- ]+$/ and next; # separator
            $line =~ m!^(?P<local_host>\S+?)\.(?P<local_port>\w+)\s+
                       (?P<foreign_host>\S+?)\.(?P<foreign_port>\w+|\*)\s+
                       (?P<state>\S+)
                       \s*$!x
                           or return [400, "Can't parse udp line (#$i): $line"];
            %k = %+;
            $k{proto} = $proto;
        } elsif ($proto =~ /tcp/ && $tcp) {
            #TCP: IPv4
            #   Local Address        Remote Address    Swind Send-Q Rwind Recv-Q    State
            #-------------------- -------------------- ----- ------ ----- ------ -----------
            #8.8.17.4.1337    8.8.213.120.65472 262140      0 1049920      0 ESTABLISHED
            $line =~ /^\s*$/ and next; # blank line
            $line =~ /^\s+/ and next; # header
            $line =~ /^[- ]+$/ and next; # separator
            $line =~ m!^(?P<local_host>\S+?)\.(?P<local_port>\w+)\s+
                       (?P<foreign_host>\S+?)\.(?P<foreign_port>\w+|\*)\s+
                       (?P<swind>\d+) \s+
                       (?P<sendq>\d+) \s+
                       (?P<rwind>\d+) \s+
                       (?P<recvq>\d+) \s+
                       (?P<state>\S+)
                       \s*$!x
                           or return [400, "Can't parse tcp line (#$i): $line"];
            %k = %+;
            $k{proto} = $proto;
        } elsif ($proto eq 'unix' && $unix) {
            #Active UNIX domain sockets
            #Address  Type          Vnode     Conn  Local Addr      Remote Addr
            #30258256428 stream-ord 00000000 00000000
            $line =~ /^\s*$/ and next; # blank line
            $line =~ /^Address\s/ and next; # header
            #$line =~ /^[- ]+$/ and next; # separator
            $line =~ m!^(?P<address>[0-9a-f]+)\s+
                       (?P<type>\S+)\s+
                       (?P<vnode>[0-9a-f]+)\s+
                       (?P<conn>[0-9a-f]+)\s+
                       (?:
                           (?P<local_addr>\S+)\s+
                           (?:
                               (?P<remote_addr>\S+)\s+
                           )?
                       )?
                       \s*$!x
                           or return [400, "Can't parse unix line (#$i): $line"];
            %k = %+;
            $k{proto} = $proto;
        } else {
            # XXX error? because there are no other lines
            next;
        }
        push @conns, \%k;
    }

    [200, "OK", {active_conns => \@conns}];
}

1;
# ABSTRACT: Parse the output of Solaris "netstat" command

=head1 SYNOPSIS

 use Parse::Netstat qw(parse_netstat);
 my $res = parse_netstat(output=>join("", `netstat -n`), flavor=>"solaris");

Sample `netstat -n` output:

# EXAMPLE: share/netstat-samples/netstat-n-solaris

Sample result:

# CODE: require Parse::Netstat::solaris; Parse::Netstat::solaris::parse_netstat(output => do { local $/; open my $fh, "<", "share/netstat-samples/netstat-n-solaris" or die; ~~<$fh> });
