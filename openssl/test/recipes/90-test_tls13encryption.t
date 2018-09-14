#! /usr/bin/env perl
# Copyright 2016-2018 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the OpenSSL license (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

use OpenSSL::Test;
use OpenSSL::Test::Utils;

my $test_name = "tls13encryption";
setup($test_name);

plan skip_all => "$test_name is not supported in this build"
    if disabled("tls1_3");

plan skip_all => "This test is unsupported in a shared library build on Windows"
    if $^O eq 'MSWin32' && !disabled("shared");

plan tests => 1;

ok(run(test(["tls13encryptiontest"])), "running tls13encryptiontest");
