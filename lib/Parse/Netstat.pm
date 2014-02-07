package Parse::Netstat;

use 5.010001;
use strict;
use warnings;

use Regexp::IPv6 qw($IPv6_re);

use Exporter;
our @ISA = qw(Exporter);
our @EXPORT_OK = qw(parse_netstat);

# VERSION

our %SPEC;

$SPEC{parse_netstat} = {
    v => 1.1,
    summary => 'Parse the output of Unix "netstat -np | -anp" command',
    description => <<'_',

Netstat can be called with `-n` (show raw IP addresses and port numbers instead
of hostnames or port names) or without. It can be called with `-a` (show all
listening and non-listening socket) option or without. And can be called with
`-p` (show PID/program names) or without.

_
    args => {
        output => {
            summary => 'Output of netstat command',
            description => <<'_',

This function only parses program's output. You need to invoke "netstat" on your
own.

_
            schema => 'str*',
            pos => 0,
            req => 1,
            cmdline_src => 'stdin_or_files',
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

    my @conns;
    my $i = 0;
    for my $line (split /^/, $output) {
        $i++;
        my %k;
        if ($line =~ /^tcp/ && $tcp) {
            #Proto Recv-Q Send-Q Local Address               Foreign Address             State       PID/Program name
            #tcp        0      0 0.0.0.0:8898                0.0.0.0:*                   LISTEN      5566/daemon2.pl [pa
            $line =~ m!^(?P<proto>tcp6?) \s+ (?P<recvq>\d+) \s+ (?P<sendq>\d+)\s+
                       (?P<local_host>\S+?):(?P<local_port>\w+)\s+
                       (?P<foreign_host>\S+?):(?P<foreign_port>\w+|\*)\s+
                       (?P<state>\S+) (?: \s+ (?:
                               (?P<pid>\d+)/(?P<program>.+?) |
                               -
                       ))? \s*$!x
                           or return [400, "Can't parse tcp line (#$i): $line"];
            %k = %+;
        } elsif ($line =~ /^udp/ && $udp) {
            #udp        0      0 0.0.0.0:631                 0.0.0.0:*                               2769/cupsd
            $line =~ m!^(?P<proto>udp6?) \s+ (?P<recvq>\d+) \s+ (?P<sendq>\d+)\s+
                       (?P<local_host>\S+?):(?P<local_port>\w+)\s+
                       (?P<foreign_host>\S+?):(?P<foreign_port>\w+|\*)\s+
                       (?P<state>\S+)? (?: \s+ (?:
                               (?P<pid>\d+)/(?P<program>.+?) |
                               -
                       ))? \s*$!x
                           or return [400, "Can't parse udp line (#$i): $line"];
            %k = %+;
        } elsif ($line =~ /^unix/ && $unix) {
            #Proto RefCnt Flags       Type       State         I-Node PID/Program name    Path
            #    unix  2      [ ACC ]     STREAM     LISTENING     650654 30463/gconfd-2      /tmp/orbit-t1/linc-76ff-0-3fc1dd3f2f2
            $line =~ m!^(?P<proto>unix) \s+ (?P<refcnt>\d+) \s+
                       \[\s*(?P<flags>\S*)\s*\] \s+ (?P<type>\S+) \s+
                       (?P<state>\S+|\s+) \s+ (?P<inode>\d+) \s+
                       (?: (?: (?P<pid>\d+)/(?P<program>.+?) | - ) \s+)?
                       (?P<path>.*?)\s*$!x
                           or return [400, "Can't parse unix line (#$i): $line"];
            %k = %+;
        } else {
            next;
        }
        push @conns, \%k;
    }

    [200, "OK", {active_conns => \@conns}];
}

1;
# ABSTRACT: Parse the output of Unix "netstat" command
__END__

=head1 SYNOPSIS

 use Parse::Netstat qw(parse_netstat);

 my $output = `netstat -anp`;
 my $res = parse_netstat output => $output;

Sample result:

 [
  200,
  "OK",
  {
    active_conns => [
      {
        foreign_host => "0.0.0.0",
        foreign_port => "*",
        local_host => "127.0.0.1",
        local_port => 1027,
        proto => "tcp",
        recvq => 0,
        sendq => 0,
        state => "LISTEN",
      },
      ...
      {
        foreign_host => "0.0.0.0",
        foreign_port => "*",
        local_host => "192.168.0.103",
        local_port => 56668,
        proto => "udp",
        recvq => 0,
        sendq => 0,
      },
      ...
      {
        flags   => "ACC",
        inode   => 15631,
        path    => "\@/tmp/dbus-VS3SLhDMEu",
        pid     => 4513,
        program => "dbus-daemon",
        proto   => "unix",
        refcnt  => 2,
        state   => "LISTENING",
        type    => "STREAM",
      },
    ],
  }
 ]


=head1 DESCRIPTION

This module provides parse_netstat().


=head1 SEE ALSO

=cut
