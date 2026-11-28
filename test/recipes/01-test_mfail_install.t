#! /usr/bin/env perl
# Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

use strict;
use warnings;

use OpenSSL::Test qw(:DEFAULT result_file slurp_file with);

setup("test_mfail_install");

# Disabling mfail lets the helper report its constructor support even if a
# linked library has already used libcrypto's allocator.
my $control_err = result_file("disabled.err");
my ($control_ok, $tap);
{
    local $ENV{OPENSSL_TEST_MFAIL_DISABLE} = 1;
    $tap = join("", run(test(["mfail_install_test"], stderr => $control_err),
                        capture => 1, statusvar => \$control_ok));
}
my $control_diagnostic = slurp_file($control_err);
my $skip_reason = "The compiler has no constructor attribute";
plan skip_all => $skip_reason
    if $control_ok && $tap =~ /^\s*ok 1 - test_mfail_disabled # skipped\s*$/m
       && $control_diagnostic =~ /\Q$skip_reason\E/;

plan tests => 7;

ok($control_ok, "the helper exits successfully with mfail disabled");
like($tap, qr/^\s*ok 1 - test_mfail_disabled\s*$/m,
     "the test ran and found the hooks disabled");
unlike($control_diagnostic, qr/MFAIL installation failed/,
       "the disabled run reports no installation failure");

my $failure_err = result_file("enabled.err");
# The native OpenVMS C runtime uses 2 for EXIT_FAILURE.
my $is_exit_failure = sub {
    my $status = shift;
    return $status == 1 || ($^O eq "VMS" && $status == 2);
};
with({ exit_checker => $is_exit_failure }, sub {
    local $ENV{OPENSSL_TEST_MFAIL_DISABLE};
    delete $ENV{OPENSSL_TEST_MFAIL_DISABLE};
    ok(run(test(["mfail_install_test"], stderr => $failure_err)),
       "the helper exits with EXIT_FAILURE when installation fails");
});

my $diagnostic = slurp_file($failure_err);
like($diagnostic, qr/^# MFAIL installation failed/m,
     "reports the failure on stderr");
like($diagnostic, qr/default allocator was used before main\(\)/,
     "explains why hook installation failed");
like($diagnostic, qr/OPENSSL_TEST_MFAIL_DISABLE=1/, "identifies the opt-out");
