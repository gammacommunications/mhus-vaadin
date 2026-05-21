(() => {
  // Disable for ETC.

  if (location.hostname.includes("etc")) {
    console.log("Detected ETC context. Skip SSO logic.");

    return;
  }

  // Someone overwrote the crypto-object. We mitigate this here.
  // Source: https://geraintluff.github.io/sha256/

  const sha256 = function a(b) {
    function c(a, b) {
      return (a >>> b) | (a << (32 - b));
    }
    for (
      var d,
        e,
        f = Math.pow,
        g = f(2, 32),
        h = "length",
        i = "",
        j = [],
        k = 8 * b[h],
        l = (a.h = a.h || []),
        m = (a.k = a.k || []),
        n = m[h],
        o = {},
        p = 2;
      64 > n;
      p++
    )
      if (!o[p]) {
        for (d = 0; 313 > d; d += p) o[d] = p;
        ((l[n] = (f(p, 0.5) * g) | 0), (m[n++] = (f(p, 1 / 3) * g) | 0));
      }
    for (b += "\x80"; (b[h] % 64) - 56; ) b += "\x00";
    for (d = 0; d < b[h]; d++) {
      if (((e = b.charCodeAt(d)), e >> 8)) return;
      j[d >> 2] |= e << (((3 - d) % 4) * 8);
    }
    for (j[j[h]] = (k / g) | 0, j[j[h]] = k, e = 0; e < j[h]; ) {
      var q = j.slice(e, (e += 16)),
        r = l;
      for (l = l.slice(0, 8), d = 0; 64 > d; d++) {
        var s = q[d - 15],
          t = q[d - 2],
          u = l[0],
          v = l[4],
          w =
            l[7] +
            (c(v, 6) ^ c(v, 11) ^ c(v, 25)) +
            ((v & l[5]) ^ (~v & l[6])) +
            m[d] +
            (q[d] =
              16 > d
                ? q[d]
                : (q[d - 16] +
                    (c(s, 7) ^ c(s, 18) ^ (s >>> 3)) +
                    q[d - 7] +
                    (c(t, 17) ^ c(t, 19) ^ (t >>> 10))) |
                  0),
          x =
            (c(u, 2) ^ c(u, 13) ^ c(u, 22)) +
            ((u & l[1]) ^ (u & l[2]) ^ (l[1] & l[2]));
        ((l = [(w + x) | 0].concat(l)), (l[4] = (l[4] + w) | 0));
      }
      for (d = 0; 8 > d; d++) l[d] = (l[d] + r[d]) | 0;
    }
    for (d = 0; 8 > d; d++)
      for (e = 3; e + 1; e--) {
        var y = (l[d] >> (8 * e)) & 255;
        i += (16 > y ? 0 : "") + y.toString(16);
      }
    return i;
  };

  //----------------------------------------------
  // DIY frontend library
  //----------------------------------------------

  //This is a lightweight implementation of a PKCE scheme, based on RFC7636 (see https://datatracker.ietf.org/doc/html/rfc7636).
  //No third party libraries are required.

  const LOCAL_STORAGE_PREFIX = "oauth_pkce_";
  const LOCAL_STORAGE_PKCE_STATE = LOCAL_STORAGE_PREFIX + "state";
  const LOCAL_STORAGE_PKCE_CODE_VERIFIER =
    LOCAL_STORAGE_PREFIX + "code_verifier";

  /**
   * Returns all compatibility problems or null.
   * @returns The detected compatibility problems.
   */
  const getBrowserCompatibilityProblemsOrNull = () => {
    let errorStrings = null;

    if (!window.localStorage) {
      errorStrings = "Unable to access local storage API.";
    }

    if (!window.crypto) {
      if (errorStrings !== null) {
        errorStrings += "\n";
      } else {
        errorStrings = "";
      }

      errorStrings += "Unable to access crypto API.";
    }

    return errorStrings;
  };

  /**
   * Creates the authorization URL and performs a redirect.
   * @param {string} clientId The client ID.
   * @param {string} redirectUri The redirect URI.
   * @param {string} authorizationEndpoint The authorization endpoint.
   * @param {string} requestedScopes The requested scopes (separated by whitespace).
   * @param {string} optionalQueryParametersString Optional query parameters.
   */
  const performSso = async (
    clientId,
    redirectUri,
    authorizationEndpoint,
    requestedScopes,
    optionalQueryParametersString,
  ) => {
    //Redirect to the authorization server.
    window.location = await createSsoUrl(
      clientId,
      redirectUri,
      authorizationEndpoint,
      requestedScopes,
      optionalQueryParametersString,
    );
  };

  /**
   * Returns true if a SSO response is present, based on the query parameters "code" and "error".
   * @returns True if a response is present (an expected query parameter is present).
   */
  const isSsoResponsePresent = () => {
    const searchParams = new URLSearchParams(window.location.search);

    return searchParams.has("code") || searchParams.has("error");
  };

  /**
   * Tries to process the SSO request, if the query parameter "code" is present. Fails if the query parameter "error" is present.
   * If no matching query parameter is present "null" is returned. Otherwise the token response JSON object is returned.
   * @param {string} clientId The client ID.
   * @param {string} redirectEndpoint The redirect URI.
   * @param {string} tokenEndpoint The token endpoint.
   * @returns The promise containing the access token data.
   */
  const processSsoResponseAsync = (
    clientId,
    redirectEndpoint,
    tokenEndpoint,
  ) => {
    const promise = new Promise((resolve, reject) => {
      const searchParams = new URLSearchParams(window.location.search);

      if (searchParams.has("error")) {
        let errorDescription;

        if (searchParams.has("error_description")) {
          errorDescription =
            " Description: " +
            decodeURIComponent(searchParams.get("error_description"));
        } else {
          errorDescription = "";
        }

        resetStoredData();

        const errorString = decodeURIComponent(searchParams.get("error"));

        reject(
          new Error(
            "An error occurred. Cause: " + errorString + errorDescription,
          ),
        );
      } else if (searchParams.has("code")) {
        if (searchParams.has("state")) {
          if (
            localStorage.getItem(LOCAL_STORAGE_PKCE_STATE) ===
            searchParams.get("state")
          ) {
            this.sendFormPostRequestAsync(tokenEndpoint, {
              grant_type: "authorization_code",
              code: searchParams.get("code"),
              client_id: clientId,
              redirect_uri: redirectEndpoint,
              code_verifier: localStorage.getItem(
                LOCAL_STORAGE_PKCE_CODE_VERIFIER,
              ),
            })
              .then((body) => {
                resetStoredData();

                if (body.access_token) {
                  resolve(body);
                } else {
                  reject(
                    new Error("Unable to find access token in response body."),
                  );
                }
              })
              .catch((error) => {
                resetStoredData();

                reject(error);
              });
          } else {
            resetStoredData();

            reject(
              new Error(
                "The state in the query does not match the stored state.",
              ),
            );
          }
        } else {
          resetStoredData();

          reject(new Error("Unable to find state in query, despite set code."));
        }
      } else {
        resolve(null);
      }
    });

    return promise;
  };

  /**
   * Creates the authorization URL.
   * @param {string} clientId The client ID.
   * @param {string} redirectUri The redirect URI.
   * @param {string} authorizationEndpoint The authorization endpoint.
   * @param {string} requestedScopes The requested scopes (separated by whitespace).
   * @param {string} optionalQueryParametersString Optional query parameters.
   */
  const createSsoUrl = async (
    clientId,
    redirectUri,
    authorizationEndpoint,
    requestedScopes,
    optionalQueryParametersString,
  ) => {
    //Create and store a random PKCE state.
    const pkceStateString = createRandomString();
    localStorage.setItem(LOCAL_STORAGE_PKCE_STATE, pkceStateString);

    //Create and store a random PKCE code verifier (the plaintext secret).
    const codeVerifier = createRandomString();
    localStorage.setItem(LOCAL_STORAGE_PKCE_CODE_VERIFIER, codeVerifier);

    //Hash and base64-urlencode the secret to use as the challenge.
    const codeVerifierTextByteArray = textToByteArray(codeVerifier);
    const codeVerifierTextHashByteArray = await hashDataWithSha256Async(
      codeVerifierTextByteArray,
    );
    const codeVerifierTextHashBase64 = urlEncodeCodeVerifierHash(
      codeVerifierTextHashByteArray,
    );

    //Build the authorization URL.
    let url =
      authorizationEndpoint +
      "?response_type=code" +
      "&client_id=" +
      encodeURIComponent(clientId) +
      "&state=" +
      encodeURIComponent(pkceStateString) +
      "&scope=" +
      encodeURIComponent(requestedScopes) +
      "&redirect_uri=" +
      encodeURIComponent(redirectUri) +
      "&code_challenge=" +
      encodeURIComponent(codeVerifierTextHashBase64) +
      "&code_challenge_method=S256" +
      "&ui_locales=" +
      encodeURIComponent(navigator.language);

    if (
      optionalQueryParametersString &&
      optionalQueryParametersString.trim().length > 0
    ) {
      url += optionalQueryParametersString;
    }

    return url;
  };

  /**
   * Creates a cryptographically random string.
   * @param {number} charactersCount Chars count.
   * @returns The created string.
   */
  const createRandomString = (charactersCount = 128) => {
    //See https://datatracker.ietf.org/doc/html/rfc7636#section-4

    const characters =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";
    const charactersLength = characters.length;

    const randomValues = new Uint32Array(charactersCount);
    window.crypto.getRandomValues(randomValues);

    let resultString = "";

    for (let tmpIndex = 0; tmpIndex < charactersCount; tmpIndex++) {
      const tmpRandomIndex = randomValues[tmpIndex] % charactersLength;
      resultString += characters.charAt(tmpRandomIndex);
    }

    return resultString;
  };

  /**
   * Converts a string to a byte array.
   * @param {string} textToHash The string to convert.
   * @returns The byte array representation.
   */
  const textToByteArray = (textToHash) => {
    const textEncoder = new TextEncoder();
    const encodedTextByteArray = textEncoder.encode(textToHash);

    return encodedTextByteArray;
  };

  /**
   * Creates a SHA256 hash.
   * @param {Uint8Array} dataToHash The data to hash.
   * @returns The created hash.
   */
  const hashDataWithSha256Async = (dataToHash) => {
    return sha256(dataToHash);
  };

  /**
   * URL encodes a string.
   * @param {string} stringToEncode The string to encode.
   * @returns The encoded string.
   */
  const urlEncodeCodeVerifierHash = (stringToEncode) => {
    return btoa(stringToEncode)
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/, "");
  };

  /**
   * Resets all stored data, including the current set history state (URL).
   */
  const resetStoredData = () => {
    window.history.replaceState(
      null,
      null,
      window.location.origin + window.location.pathname,
    );

    localStorage.removeItem(LOCAL_STORAGE_PKCE_STATE);
    localStorage.removeItem(LOCAL_STORAGE_PKCE_CODE_VERIFIER);
  };

  /**
   * Performs a HTTP POST request, with an excpected 200 OK status code, to obtain the response body (a JSON object).
   * @param {string} url The URL to post to.
   * @param {string} contentType The content type of the request (optional).
   * @param {object} keyValueParameters Object as key value body parameters (optional).
   * @param {object} keyValueHeaders Object as key value header parameters (optional).
   * @returns The response JSON body.
   */
  const sendPostRequestAsync = (
    url,
    contentType = null,
    keyValueParameters = null,
    keyValueHeaders = null,
  ) => {
    const promise = new Promise((resolve, reject) => {
      const request = new XMLHttpRequest();

      request.open("POST", url, true);

      if (contentType !== null) {
        request.setRequestHeader("Content-Type", contentType);
      }

      if (keyValueHeaders !== null) {
        Object.keys(keyValueHeaders).forEach((tmpKey) => {
          request.setRequestHeader(tmpKey, keyValueHeaders[tmpKey]);
        });
      }

      request.onload = () => {
        if (request.status === 200) {
          try {
            const responseBody = JSON.parse(request.response);
            resolve(responseBody);
          } catch (error) {
            reject(error);
          }
        } else {
          reject(
            new Error(
              "Unable to perform successful POST request (received status code " +
                request.status +
                ").",
            ),
          );
        }
      };

      request.onerror = () => {
        reject(new Error("Unable to perform POST request."));
      };

      let requestBodyString;

      if (keyValueParameters !== null) {
        requestBodyString = Object.keys(keyValueParameters)
          .map((tmpKey) => tmpKey + "=" + keyValueParameters[tmpKey])
          .join("&");
      } else {
        requestBodyString = "";
      }

      request.send(requestBodyString);
    });

    return promise;
  };

  /**
   * Performs a HTTP POST request, with an expected 200 OK status code, to obtain the response body (a JSON object).
   * @param {string} url The URL to post to.
   * @param {object} keyValueParameters Object as key value body parameters (optional).
   * @param {object} keyValueHeaders Object as key value header parameters (optional).
   * @returns The response JSON body.
   */
  const sendFormPostRequestAsync = (
    url,
    keyValueParameters = null,
    keyValueHeaders = null,
  ) => {
    return this.sendPostRequestAsync(
      url,
      "application/x-www-form-urlencoded; charset=UTF-8",
      keyValueParameters,
      keyValueHeaders,
    );
  };

  /**
   * Performs a HTTP POST request, with an expected 200 OK status code, to obtain the response body (a JSON object).
   * @param {string} url The URL to post to.
   * @param {object} keyValueParameters Object as key value body parameters (optional).
   * @param {object} keyValueHeaders Object as key value header parameters (optional).
   * @returns The response JSON body.
   */
  const sendJsonPostRequestAsync = (
    url,
    keyValueParameters = null,
    keyValueHeaders = null,
  ) => {
    return this.sendPostRequestAsync(
      url,
      keyValueParameters,
      "application/json; charset=UTF-8",
      keyValueParameters,
      keyValueHeaders,
    );
  };

  //----------------------------------------------
  // Actual logic (must be executed always)
  //----------------------------------------------

  function setFavicon(dataUrl) {
    // Remove all existing favicons.

    document
      .querySelectorAll(
        "link[rel='icon'], link[rel='shortcut icon'], link[rel='apple-touch-icon']",
      )
      .forEach((tmpElement) => tmpElement.parentNode.removeChild(tmpElement));

    // Create new favicon link.

    const link = document.createElement("link");

    link.rel = "icon";
    link.href = dataUrl;

    document.head.appendChild(link);
  }

  const logoSvg =
    "data:image/svg+xml,%3csvg%20version='1.2'%20xmlns='http://www.w3.org/2000/svg'%20viewBox='0%200%201594%201435'%20width='1594'%20height='1435'%3e%3cpath%20fill='%236800d2'%20id='Layer'%20fill-rule='evenodd'%20class='s0'%20d='m1195.9%2030.4c99.3%2058.6%20133.2%20185%2074.5%20284.3-58.7%2099.3-185%20133.1-284.3%2074.4-99.3-58.6-133.2-185-74.5-284.3%2058.7-99.2%20185-133.1%20284.3-74.4zm-988.3%20893.5c-114.8%200-207.6-92.8-207.6-207.6%200-114.8%2092.8-207.6%20207.6-207.6%20114.8%200%20207.6%2092.8%20207.6%20207.6%200%20114.8-92.8%20207.6-207.6%20207.6zm194.1-898c101.5-54.2%20227.9-18.1%20282%2083.4%2054.2%20101.6%2018.1%20227.9-83.5%20282.1-101.5%2054.1-227.9%2018-282-83.5-54.2-101.5-18.1-227.9%2083.5-282zm787.5%201383.1c-101.6%2054.1-227.9%2018-282.1-83.5-54.2-101.5-18.1-227.9%2083.5-282%20101.5-54.2%20227.9-18.1%20282%2083.4%2056.5%20101.6%2018.1%20225.7-83.4%20282.1zm-794.3-4.5c-99.3-58.7-133.1-185-74.5-284.3%2058.7-99.3%20185-133.1%20284.3-74.5%2099.3%2058.7%20133.2%20185%2074.5%20284.3-56.4%2099.3-185%20133.1-284.3%2074.5zm843.9-834.9c36.1-38.3%2090.3-60.9%20146.7-60.9%20115.1%200%20207.6%2092.5%20207.6%20207.6%200%20115.1-92.5%20207.6-207.6%20207.6-56.4%200-108.3-22.6-146.7-60.9-103.8-103.8-191.8-103.8-295.6%200-36.1%2038.3-90.3%2060.9-146.7%2060.9-115%200-207.6-92.5-207.6-207.6%200-115.1%2092.6-207.6%20207.6-207.6%2056.4%200%20108.3%2022.6%20146.7%2060.9%20103.8%20103.8%20191.8%20103.8%20295.6%200z'/%3e%3c/svg%3e";

  setFavicon(logoSvg);

  // Find table to mofify or fail.

  const tableElement = document.querySelector(
    "div.v-formlayout-login-form > table",
  );

  if (tableElement) {
    // Modify DOM.

    tableElement.style.display = "none";

    const formElement = document.querySelector("div.v-formlayout-login-form");
    formElement.style.fontFamily = "Mulish, Helvetica, sans-serif";

    const logoElement = document.createElement("img");
    logoElement.style = "width: 7em; margin-left: 5.5em; margin-top: 1em;";
    logoElement.src = logoSvg;

    formElement.appendChild(logoElement);

    formElement.appendChild(document.createElement("br"));

    const btnOauthLoginSubmitElement = document.createElement("button");
    btnOauthLoginSubmitElement.innerText = "Login mit SSO";
    btnOauthLoginSubmitElement.style =
      "background-color: #6800d2; color: #fff; border-radius: 2em; margin: 2em; padding-left: 1.2em; padding-right: 1.2em; padding-top: 0.2em; padding-bottom: 0.2em; width: 14em; cursor: pointer;";

    formElement.appendChild(btnOauthLoginSubmitElement);

    // Do SSO stuff (prepare or submit SSO data).

    //SSO configuration.

    let oauthConfig;

    if (!location.hostname.includes("qs")) {
      //Set the prod configuration.

      oauthConfig = {
        clientId: "de.gammacommunications.magic-control-panel",
        redirectPathSuffix: "/ui",
        authorizationEndpoint:
          "https://login.gamma-portal.com/realms/europe/protocol/openid-connect/auth",
        requestedScopes: "openid email",
        tokenEndpoint:
          "https://login.gamma-portal.com/realms/europe/protocol/openid-connect/token",
      };
    } else {
      //Set the QS configuration.

      oauthConfig = {
        clientId: "de.gammacommunications.magic-control-panel",
        redirectPathSuffix: "/ui",
        authorizationEndpoint:
          "https://login-lab.gamma-portal.com/realms/dev-europe/protocol/openid-connect/auth",
        requestedScopes: "openid email",
        tokenEndpoint:
          "https://login-lab.gamma-portal.com/realms/dev-europe/protocol/openid-connect/token",
      };
    }

    //Username which is used during SSO.

    const AUTH_TYPE_KEYCLOAK_ACCESS_TOKEN_USERNAME =
      "AUTH_TYPE_KEYCLOAK_ACCESS_TOKEN";

    //Find all DOM elements.

    const regularUsernameFieldElement = document.querySelector(
      'td > input[type="text"]',
    );
    const regularPasswordFieldElement = document.querySelector(
      'td > input[type="password"]',
    );
    const regularButtonLoginSubmitElement = document.querySelector(
      "div.v-button.v-widget",
    );

    //Create port string if set.

    let portString = "";

    if (location.port !== "") {
      portString = ":" + location.port;
    }

    //Show SSO login button only if the browser is compatible.

    const compatibilityProblems = getBrowserCompatibilityProblemsOrNull();

    if (compatibilityProblems !== null) {
      console.error("Unable to enable SSO login. Cause:");
      console.error(compatibilityProblems);

      btnOauthLoginSubmitElement.style.display = "none";
      return;
    }

    //DOM logic.

    btnOauthLoginSubmitElement.addEventListener("click", (event) => {
      //Always cancel the form POST!
      event.preventDefault();

      //Triggers the initial PKCE SSO request.
      const ssoRedirectUrl =
        location.protocol +
        "//" +
        location.hostname +
        portString +
        oauthConfig.redirectPathSuffix;

      performSso(
        oauthConfig.clientId,
        ssoRedirectUrl,
        oauthConfig.authorizationEndpoint,
        oauthConfig.requestedScopes,
      );
    });

    //The following logic checks the current URL for query parameters from the SSO redirect.

    if (isSsoResponsePresent()) {
      //Adjust waiting view.

      btnOauthLoginSubmitElement.disabled = "true";

      //Process SSO response.

      const ssoRedirectUrl =
        location.protocol +
        "//" +
        location.hostname +
        portString +
        oauthConfig.redirectPathSuffix;

      processSsoResponseAsync(
        oauthConfig.clientId,
        ssoRedirectUrl,
        oauthConfig.tokenEndpoint,
      )
        .then((response) => {
          sessionStorage.setItem("idToken", response.id_token);

          regularUsernameFieldElement.value =
            AUTH_TYPE_KEYCLOAK_ACCESS_TOKEN_USERNAME;

          regularPasswordFieldElement.value = response.access_token;

          regularButtonLoginSubmitElement.click();
        })
        .catch((error) => {
          console.error("An error occurred: ");
          console.error(error);

          alert(
            "Access token could not be retrieved. Please try again. If the problem persists, please contact support.",
          );

          btnOauthLoginSubmitElement.disabled = "";
        });
    } else {
      console.log("No SSO response is present.");
    }
  } else {
    console.error("Unable to find login-form table! Show legacy login...");
  }
})();
