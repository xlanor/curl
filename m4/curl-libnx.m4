#***************************************************************************
#                                  _   _ ____  _
#  Project                     ___| | | |  _ \| |
#                             / __| | | | |_) | |
#                            | (__| |_| |  _ <| |___
#                             \___|\___/|_| \_\_____|
#
# Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
#
# This software is licensed as described in the file COPYING, which
# you should have received as part of this distribution. The terms
# are also available at https://curl.se/docs/copyright.html.
#
# You may opt to use, copy, modify, merge, publish, distribute and/or sell
# copies of the Software, and permit persons to whom the Software is
# furnished to do so, under the terms of the COPYING file.
#
# This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
# KIND, either express or implied.
#
# SPDX-License-Identifier: curl
#
#***************************************************************************

AC_DEFUN([CURL_WITH_LIBNX], [
dnl ----------------------------------------------------
dnl check for libnx (Nintendo Switch TLS backend)
dnl ----------------------------------------------------

if test "x$OPT_LIBNX" != "xno"; then
  ssl_msg=

  dnl libnx is provided by the devkitPro Nintendo Switch toolchain
  dnl No pkg-config or library discovery is needed as the toolchain
  dnl provides everything

  AC_MSG_NOTICE([libnx TLS backend requested])

  AC_DEFINE(USE_LIBNX, 1, [if libnx is enabled])
  USE_LIBNX="yes"
  LIBNX_ENABLED=1
  ssl_msg="libnx"
  test "libnx" != "$DEFAULT_SSL_BACKEND" || VALID_DEFAULT_SSL_BACKEND=yes

  check_for_ca_bundle=1

  test -z "$ssl_msg" || ssl_backends="${ssl_backends:+$ssl_backends, }$ssl_msg"
fi
])
