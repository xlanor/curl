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
 *
 * Based on the devkitPro curl fork by yellows8.
 */

#include "curl_setup.h"

#ifdef USE_LIBNX

#undef BIT
#include <switch.h>
#undef BIT
#define BIT(x) bit x:1
#include <string.h>

#include "hos.h"
#include "urldata.h"
#include "sendf.h"
#include "setopt.h"

/*
 * Get system proxy settings from the Nintendo Switch network configuration.
 *
 * This function queries the nifm (Network Interface Manager) service to
 * get the current network profile's proxy settings. If a proxy is configured,
 * it sets the appropriate curl options.
 */
CURLcode Curl_hos_get_system_proxy(struct Curl_easy *data)
{
  Result rc;
  NifmNetworkProfileData profile;
  NifmProxySetting *proxy;
  char proxy_url[256];
  CURLcode result = CURLE_OK;

  /* Initialize nifm service */
  rc = nifmInitialize(NifmServiceType_User);
  if(R_FAILED(rc)) {
    /* nifm not available - not an error, just no proxy detection */
    infof(data, "libnx: nifm service not available for proxy detection");
    return CURLE_OK;
  }

  /* Get current network profile */
  rc = nifmGetCurrentNetworkProfile(&profile);
  if(R_FAILED(rc)) {
    nifmExit();
    /* No network profile - not an error */
    infof(data, "libnx: no network profile available");
    return CURLE_OK;
  }

  /* Check if proxy is enabled in the profile */
  proxy = &profile.ip_setting_data.proxy_setting;

  if(!proxy->enabled) {
    nifmExit();
    /* Proxy not enabled - no action needed */
    return CURLE_OK;
  }

  /* Proxy is enabled - build the proxy URL */
  if(proxy->port == 0) {
    nifmExit();
    /* Invalid proxy port */
    return CURLE_OK;
  }

  /* Construct proxy URL: http://server:port */
  snprintf(proxy_url, sizeof(proxy_url), "http://%s:%u",
           proxy->server, proxy->port);

  infof(data, "libnx: using system proxy: %s", proxy_url);

  /* Set the proxy */
  result = Curl_setstropt(&data->set.str[STRING_PROXY], proxy_url);
  if(result != CURLE_OK) {
    nifmExit();
    return result;
  }

  /* Set proxy authentication if enabled */
  if(proxy->auto_auth_enabled) {
    /* Set proxy username */
    if(proxy->user[0] != '\0') {
      result = Curl_setstropt(&data->set.str[STRING_PROXYUSERNAME],
                              proxy->user);
      if(result != CURLE_OK) {
        nifmExit();
        return result;
      }
    }

    /* Set proxy password */
    if(proxy->password[0] != '\0') {
      result = Curl_setstropt(&data->set.str[STRING_PROXYPASSWORD],
                              proxy->password);
      if(result != CURLE_OK) {
        nifmExit();
        return result;
      }
    }

    infof(data, "libnx: proxy authentication configured");
  }

  nifmExit();
  return CURLE_OK;
}

#endif /* USE_LIBNX */
