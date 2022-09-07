#!/usr/bin/perl
# Copyright (c) 2022 EEMBC
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

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

