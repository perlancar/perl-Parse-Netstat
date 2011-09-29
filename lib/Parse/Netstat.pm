package Parse::Netstat;

use 5.010;
use strict;
use warnings;

use Exporter::Lite;
our @EXPORT_OK = qw(parse_netstat);

# VERSION

our %SPEC;

$SPEC{parse_netstat} = {
    summary => 'Parse the output of Unix "netstat" command',
    args => {
        output => ['str*' => {
            arg_pos => 0,
            summary => 'Output of netstat command',
            description => <<'_',

This function only parses program's output. You need to invoke "netstat" on your
own.

_
        }],
        tcp => ['bool' => {
            summary => 'Whether to parse tcp connections',
            default => 1,
        }],
        udp => ['bool' => {
            summary => 'Whether to parse udp connections',
            default => 1,
        }],
        unix => ['bool' => {
            summary => 'Whether to parse unix connections',
            default => 1,
        }],
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
            $line =~ m!^(?<proto>tcp) \s+ (?<recvq>\d+) \s+ (?<sendq>\d+)\s+
                       (?<local_host>\S+?):(?<local_port>\w+)\s+
                       (?<foreign_host>\S+?):(?<foreign_port>\w+|\*)\s+
                       (?<state>\S+) (?: \s+ (?:
                               (?<pid>\d+)/(?<program>\S+) |
                               -
                       ))? \s*$!x
                           or return [400, "Invalid tcp line (#$i): $line"];
            %k = %+;
        } elsif ($line =~ /^udp/ && $udp) {
            #udp        0      0 0.0.0.0:631                 0.0.0.0:*                               2769/cupsd
            $line =~ m!^(?<proto>udp) \s+ (?<recvq>\d+) \s+ (?<sendq>\d+)\s+
                       (?<local_host>\S+?):(?<local_port>\w+)\s+
                       (?<foreign_host>\S+?):(?<foreign_port>\w+|\*)\s+
                       (?: \s+ (?:
                               (?<pid>\d+)/(?<program>\S+) |
                               -
                       ))? \s*$!x
                           or return [400, "Invalid udp line (#$i): $line"];
            %k = %+;
        } elsif ($line =~ /^unix/ && $unix) {
            #Proto RefCnt Flags       Type       State         I-Node PID/Program name    Path
            #    unix  2      [ ACC ]     STREAM     LISTENING     650654 30463/gconfd-2      /tmp/orbit-t1/linc-76ff-0-3fc1dd3f2f2
            $line =~ m!^(?<proto>unix) \s+ (?<refcnt>\d+) \s+
                       \[\s*(?<flags>\S*)\s*\] \s+ (?<type>\S+) \s+
                       (?<state>\S+|\s+) \s+ (?<inode>\d+) \s+
                       (?: (?: (?<pid>\d+)/(?<program>\S+) | - ) \s+)?
                       (?<path>.*?)\s*$!x
                           or return [400, "Invalid unix line (#$i): $line"];
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


=head1 FUNCTIONS

None are exported by default, but they are exportable.


=head1 SEE ALSO

=cut
