/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/crypto.h>
#include "testutil.h"

#if defined(__has_attribute)
#if __has_attribute(constructor)
#define HAVE_CONSTRUCTOR_ATTRIBUTE 1
#endif
#elif defined(__GNUC__)
/* GCC has the constructor attribute, but no __has_attribute before GCC 5 */
#define HAVE_CONSTRUCTOR_ATTRIBUTE 1
#endif

#ifdef HAVE_CONSTRUCTOR_ATTRIBUTE
/* Use the default allocator before testutil's main() installs mfail. */
__attribute__((constructor)) static void allocate_before_main(void)
{
    OPENSSL_free(OPENSSL_malloc(16));
}
#endif

static int test_mfail_disabled(void)
{
#ifdef HAVE_CONSTRUCTOR_ATTRIBUTE
    return TEST_false(mfail_is_installed());
#else
    return TEST_skip("The compiler has no constructor attribute");
#endif
}

int setup_tests(void)
{
    ADD_TEST(test_mfail_disabled);
    return 1;
}
