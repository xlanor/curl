#ifndef HEADER_CURL_HOS_H
#define HEADER_CURL_HOS_H
/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at https://curl.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 * SPDX-License-Identifier: curl
 *
 ***************************************************************************/

/*
 * Nintendo Switch (Horizon OS) specific functionality.
 * Provides system proxy detection via nifm service.
 */

#include "curl_setup.h"

#ifdef USE_LIBNX

struct Curl_easy;

/*
 * Get system proxy settings from the Nintendo Switch network configuration.
 * Uses nifmGetCurrentNetworkProfile() to retrieve proxy settings.
 *
 * Returns CURLE_OK on success (even if no proxy is configured),
 * or an error code on failure.
 */
CURLcode Curl_hos_get_system_proxy(struct Curl_easy *data);

#else

/* No-op on non-Switch platforms */
#define Curl_hos_get_system_proxy(x) CURLE_OK

#endif /* USE_LIBNX */

#endif /* HEADER_CURL_HOS_H */
