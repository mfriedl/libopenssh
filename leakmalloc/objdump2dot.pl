#!/usr/bin/perl

use Data::Dumper;
use Getopt::Std;
use strict;
use warnings;

sub usage () {
	my $argv0 = $0;
	$argv0 =~ s|.*/||;
	printf "usage: objdump -rd *.o | $argv0 [-rb] f1 [f2...] | dot -Tpdf > out.pdf\n";
	exit 1;
}

my %opts;
getopts('brd', \%opts) or usage();
$#ARGV >= 0 or usage();
my $reverse = $opts{r} || 0;	# print callers, otherwise callee-s
my $both = $opts{b} || 0;
my $debug = $opts{d} || 0;
my @functions = @ARGV;
@ARGV=();

## parse Relocated-Disassemble output from 'objdump -rd'
##00000000 <ASN1_d2i_fp>:
##   9:	e8 00 00 00 00       	call   e <ASN1_d2i_fp+0xe>	NOT
##			16: R_386_PLT32	BIO_s_file		YES
##			1e: R_386_PLT32	BIO_new			YES
## 106:	e8 c5 00 00 00       	call   1d0 <asn1_d2i_read_bio>	YES

my $graph = {};
my $inverse = {};

# check for function calls and build call-graph
my $caller = '';
while(<>) {
	chomp;
	if (/^\S+ <(\S+)>:/) {
		$caller=$1;
		$caller='' if $caller =~ /^\./;
		print "# FOUND FUNC $1\n" if $caller && $debug;
	}
	next unless $caller;
	if (/(R_386_PC32|R_386_PLT32)\s+(\S+)/) {
		my $f=$2;
		print "# $caller => $f\n" if $debug;
		$graph->{$caller}->{$f} = 1;
	} 
	if (/call\s.+<(\S+)>/) {
		my $f=$1;
		next if ($f =~ /\+0x/);
		print "# $caller -> $f\n" if $debug;
		$graph->{$caller}->{$f} = 1;
	}
}
print Dumper($graph) if $debug;

if ($reverse || $both) {
	# build the inverse call graph (callee->caller)
	while (my ($caller, $calls) = each %$graph) {
		foreach my $f (sort keys %$calls) {
			$inverse->{$f}->{$caller} = 1;
		}
	}
	print Dumper($inverse) if $debug;
}

# recurse over the call-graph ($map) until no callers
# are found, skip if already seen (by deleting them)
sub show {
	my $func = shift;
	my $map = shift;
	my $entry = delete $map->{$func};
	if (defined($entry)) {
		foreach my $f (sort keys %{$entry}) {
			if ($map == $inverse) {
				printf "$f -> $func\n";
			} else {
				printf "$func -> $f\n";
			}
			show($f, $map);
		}
	}
}

print "digraph callgraph {\n";
print "rankdir=LR\n";	# left-to-right
foreach my $f (@functions) {
	if ($reverse || $both) {
		show($f, $inverse);
	}
	if (!$reverse || $both) {
		show($f, $graph);
	}
	print "$f [color=red]\n";
}
print "}\n";
