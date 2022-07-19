#!/usr/bin/perl


use warnings;
use strict;
use Data::Dumper;

my @table = ();

while(<>) {
    chomp;
    if (/^\d{5},/) {
        my @parts = split(/[,]+/);
        @parts = map { s/^\s*(.*?)\s*$/$1/; $_; } @parts;
        # Don't care about the first three columns
        shift @parts;
        shift @parts;
        shift @parts;
        push @table, \@parts;
    }
}

my @rowsums = ();
my @colsums = ();
my $total = 0;
my $r = 0;
my $c = 0;
foreach my $row (@table) {
    $c = 0;
    foreach my $col (@$row) {
        $col = $col eq "" ? 0 : $col;
        $colsums[$c] += $col;
        $rowsums[$r] += $col;
        ++$c;
        $total += $col;
    }
    ++$r;
}

for (my $i=0; $i<=$#colsums; ++$i) {
    printf("Column sum % 3d : % 10d\n", $i+1, $colsums[$i]);
}
for (my $i=0; $i<=$#rowsums; ++$i) {
    printf("Row sum    % 3d : % 10d\n", $i+1, $rowsums[$i]);
}
print "Total: $total\n";

