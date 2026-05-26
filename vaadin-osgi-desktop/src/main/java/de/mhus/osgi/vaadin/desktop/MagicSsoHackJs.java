package de.mhus.osgi.vaadin.desktop;

public class MagicSsoHackJs {
    //This is a simple helper class to "store" the self-executing JS function. Copy the JS-code from the ".js"-file
    //and paste it into an empty string. IntelliJ will apply the line breaks for you on paste.
    //ALWAYS update the ".js" file and copy the changes AFTERWARD into this file.

    public static final String JS_CODE = "(() => {\n" +
            "  // Disable for ETC.\n" +
            "\n" +
            "  if (location.hostname.includes(\"etc\")) {\n" +
            "    console.log(\"Detected ETC context. Skip SSO logic.\");\n" +
            "\n" +
            "    return;\n" +
            "  }\n" +
            "\n" +
            "  // There is no SHA-256 without TLS (missing crypto-API access). We mitigate this here.\n" +
            "  // Source: https://geraintluff.github.io/sha256/\n" +
            "\n" +
            "  const sha256 = function a(b) {\n" +
            "    function c(a, b) {\n" +
            "      return (a >>> b) | (a << (32 - b));\n" +
            "    }\n" +
            "    for (\n" +
            "      var d,\n" +
            "        e,\n" +
            "        f = Math.pow,\n" +
            "        g = f(2, 32),\n" +
            "        h = \"length\",\n" +
            "        i = \"\",\n" +
            "        j = [],\n" +
            "        k = 8 * b[h],\n" +
            "        l = (a.h = a.h || []),\n" +
            "        m = (a.k = a.k || []),\n" +
            "        n = m[h],\n" +
            "        o = {},\n" +
            "        p = 2;\n" +
            "      64 > n;\n" +
            "      p++\n" +
            "    )\n" +
            "      if (!o[p]) {\n" +
            "        for (d = 0; 313 > d; d += p) o[d] = p;\n" +
            "        ((l[n] = (f(p, 0.5) * g) | 0), (m[n++] = (f(p, 1 / 3) * g) | 0));\n" +
            "      }\n" +
            "    for (b += \"\\x80\"; (b[h] % 64) - 56; ) b += \"\\x00\";\n" +
            "    for (d = 0; d < b[h]; d++) {\n" +
            "      if (((e = b.charCodeAt(d)), e >> 8)) return;\n" +
            "      j[d >> 2] |= e << (((3 - d) % 4) * 8);\n" +
            "    }\n" +
            "    for (j[j[h]] = (k / g) | 0, j[j[h]] = k, e = 0; e < j[h]; ) {\n" +
            "      var q = j.slice(e, (e += 16)),\n" +
            "        r = l;\n" +
            "      for (l = l.slice(0, 8), d = 0; 64 > d; d++) {\n" +
            "        var s = q[d - 15],\n" +
            "          t = q[d - 2],\n" +
            "          u = l[0],\n" +
            "          v = l[4],\n" +
            "          w =\n" +
            "            l[7] +\n" +
            "            (c(v, 6) ^ c(v, 11) ^ c(v, 25)) +\n" +
            "            ((v & l[5]) ^ (~v & l[6])) +\n" +
            "            m[d] +\n" +
            "            (q[d] =\n" +
            "              16 > d\n" +
            "                ? q[d]\n" +
            "                : (q[d - 16] +\n" +
            "                    (c(s, 7) ^ c(s, 18) ^ (s >>> 3)) +\n" +
            "                    q[d - 7] +\n" +
            "                    (c(t, 17) ^ c(t, 19) ^ (t >>> 10))) |\n" +
            "                  0),\n" +
            "          x =\n" +
            "            (c(u, 2) ^ c(u, 13) ^ c(u, 22)) +\n" +
            "            ((u & l[1]) ^ (u & l[2]) ^ (l[1] & l[2]));\n" +
            "        ((l = [(w + x) | 0].concat(l)), (l[4] = (l[4] + w) | 0));\n" +
            "      }\n" +
            "      for (d = 0; 8 > d; d++) l[d] = (l[d] + r[d]) | 0;\n" +
            "    }\n" +
            "    for (d = 0; 8 > d; d++)\n" +
            "      for (e = 3; e + 1; e--) {\n" +
            "        var y = (l[d] >> (8 * e)) & 255;\n" +
            "        i += (16 > y ? 0 : \"\") + y.toString(16);\n" +
            "      }\n" +
            "    return i;\n" +
            "  };\n" +
            "\n" +
            "  function sha256DigestFallback(algorithm, data) {\n" +
            "    return new Promise((resolve, reject) => {\n" +
            "      try {\n" +
            "        // Match subtle.digest(...) behavior.\n" +
            "\n" +
            "        const algoName =\n" +
            "          typeof algorithm === \"string\"\n" +
            "            ? algorithm\n" +
            "            : algorithm && algorithm.name;\n" +
            "\n" +
            "        if (algoName !== \"SHA-256\") {\n" +
            "          throw new Error(\n" +
            "            \"Not supported: Only SHA-256 is implemented in this fallback.\",\n" +
            "          );\n" +
            "        }\n" +
            "\n" +
            "        // Accept ArrayBuffer, TypedArray, DataView.\n" +
            "\n" +
            "        const bytes = toUint8Array(data);\n" +
            "\n" +
            "        // Convert bytes -> binary string expected by the legacy sha256() function.\n" +
            "\n" +
            "        let binary = \"\";\n" +
            "\n" +
            "        for (let i = 0; i < bytes.length; i++) {\n" +
            "          binary += String.fromCharCode(bytes[i]);\n" +
            "        }\n" +
            "\n" +
            "        // Hash result is hex string.\n" +
            "\n" +
            "        const hex = sha256(binary);\n" +
            "\n" +
            "        if (typeof hex !== \"string\" || hex.length !== 64) {\n" +
            "          throw new Error(\"SHA-256 fallback failed.\");\n" +
            "        }\n" +
            "\n" +
            "        // Convert hex -> ArrayBuffer (exact WebCrypto-like output type).\n" +
            "\n" +
            "        const out = new Uint8Array(32);\n" +
            "\n" +
            "        for (let i = 0; i < 32; i++) {\n" +
            "          out[i] = parseInt(hex.substr(i * 2, 2), 16);\n" +
            "        }\n" +
            "\n" +
            "        resolve(out.buffer);\n" +
            "      } catch (error) {\n" +
            "        reject(error);\n" +
            "      }\n" +
            "    });\n" +
            "  }\n" +
            "\n" +
            "  function toUint8Array(data) {\n" +
            "    if (data instanceof ArrayBuffer) {\n" +
            "      return new Uint8Array(data);\n" +
            "    }\n" +
            "\n" +
            "    if (ArrayBuffer.isView(data)) {\n" +
            "      return new Uint8Array(data.buffer, data.byteOffset, data.byteLength);\n" +
            "    }\n" +
            "\n" +
            "    throw new TypeError(\n" +
            "      \"Failed to execute 'digest': parameter 2 is not of type 'ArrayBuffer' or 'ArrayBufferView'.\",\n" +
            "    );\n" +
            "  }\n" +
            "\n" +
            "  // Vaadin requires a \"real\" interaction with the current setup.\n" +
            "\n" +
            "  function simulateInteraction(targetElement, text, delay = 500) {\n" +
            "    targetElement.focus();\n" +
            "\n" +
            "    // Simulate paste event.\n" +
            "    const pasteEvent = new ClipboardEvent(\"paste\", {\n" +
            "      bubbles: true,\n" +
            "      cancelable: true,\n" +
            "      clipboardData: new DataTransfer()\n" +
            "    });\n" +
            "\n" +
            "    pasteEvent.clipboardData.setData(\"text/plain\", text);\n" +
            "\n" +
            "    targetElement.dispatchEvent(pasteEvent);\n" +
            "\n" +
            "    // Set the value.\n" +
            "    targetElement.value = text;\n" +
            "\n" +
            "    // Fire input event so frameworks detect the change.\n" +
            "    targetElement.dispatchEvent(new Event(\"input\", { bubbles: true }));\n" +
            "\n" +
            "    await new Promise((successHandler) => setTimeout(successHandler, delay));\n" +
            "  }\n" +
            "\n" +
            "\n" +
            "  // Utility to extract user-data.\n" +
            "  async function readCustomClaim(jwt, claimName) {\n" +
            "    if (typeof jwt !== \"string\") {\n" +
            "      throw new Error(\"JWT must be a string\");\n" +
            "    }\n" +
            "\n" +
            "    if (typeof claimName !== \"string\") {\n" +
            "      throw new Error(\"Claim name must be a string\");\n" +
            "    }\n" +
            "\n" +
            "    try {\n" +
            "      const parts = jwt.split(\".\");\n" +
            "      if (parts.length !== 3) {\n" +
            "        throw new Error(\"Invalid JWT format\");\n" +
            "      }\n" +
            "\n" +
            "      // Decode payload (middle part)\n" +
            "      const payloadJson = atob(parts[1].replace(/-/g, \"+\").replace(/_/g, \"/\"));\n" +
            "      const payload = JSON.parse(payloadJson);\n" +
            "\n" +
            "      if (!(claimName in payload)) {\n" +
            "        throw new Error(`Claim '${claimName}' not found in token`);\n" +
            "      }\n" +
            "\n" +
            "      return payload[claimName];\n" +
            "    } catch (err) {\n" +
            "      throw new Error(`Failed to decode JWT: ${err.message}`);\n" +
            "    }\n" +
            "  }\n" +
            "\n" +
            "  // Include legacy toggle logic.\n" +
            "\n" +
            "  function initLegacyLoginToggle() {\n" +
            "    const STORAGE_KEY = \"mgc-panel-is-legacy-login-ebabled\";\n" +
            "\n" +
            "    // Read current state from localStorage.\n" +
            "    const isEnabled = localStorage.getItem(STORAGE_KEY) === \"true\";\n" +
            "\n" +
            "    let pressTimes = [];\n" +
            "\n" +
            "    window.addEventListener(\"keydown\", function (event) {\n" +
            "      // Check for ALT + L (physical L key)\n" +
            "      if (\n" +
            "        event.altKey &&\n" +
            "        (event.code === \"KeyL\" || event.key.toLowerCase() === \"l\")\n" +
            "      ) {\n" +
            "        const now = Date.now();\n" +
            "\n" +
            "        pressTimes.push(now);\n" +
            "\n" +
            "        // Keep only last 5 seconds of interactions.\n" +
            "        pressTimes = pressTimes.filter((tmpTime) => now - tmpTime <= 5000);\n" +
            "\n" +
            "        if (pressTimes.length >= 5) {\n" +
            "          pressTimes = []; // Reset\n" +
            "\n" +
            "          const currentState = localStorage.getItem(STORAGE_KEY) === \"true\";\n" +
            "\n" +
            "          const newState = !currentState;\n" +
            "\n" +
            "          const confirmQuestion = currentState\n" +
            "            ? \"Legacy Login is currently ENABLED. Disable it?\"\n" +
            "            : \"Legacy Login is currently DISABLED. Enable it?\";\n" +
            "\n" +
            "          if (confirm(confirmQuestion)) {\n" +
            "            localStorage.setItem(STORAGE_KEY, String(newState));\n" +
            "\n" +
            "            location.reload();\n" +
            "          }\n" +
            "        }\n" +
            "      }\n" +
            "    });\n" +
            "\n" +
            "    return isEnabled;\n" +
            "  }\n" +
            "\n" +
            "  const isLegacyLoginEnabled = initLegacyLoginToggle();\n" +
            "\n" +
            "  if (isLegacyLoginEnabled) {\n" +
            "    console.log(\n" +
            "      \"Legacy login is enabled. Press ALT+L five subsequent times to disable it.\",\n" +
            "    );\n" +
            "\n" +
            "    return;\n" +
            "  } else {\n" +
            "    console.log(\n" +
            "      \"Legacy login is disabled. Press ALT+L five subsequent times to enable it.\",\n" +
            "    );\n" +
            "  }\n" +
            "\n" +
            "  //----------------------------------------------\n" +
            "  // DIY frontend library\n" +
            "  //----------------------------------------------\n" +
            "\n" +
            "  //This is a lightweight implementation of a PKCE scheme, based on RFC7636 (see https://datatracker.ietf.org/doc/html/rfc7636).\n" +
            "  //No third party libraries are required.\n" +
            "\n" +
            "  const LOCAL_STORAGE_PREFIX = \"oauth_pkce_\";\n" +
            "  const LOCAL_STORAGE_PKCE_STATE = LOCAL_STORAGE_PREFIX + \"state\";\n" +
            "  const LOCAL_STORAGE_PKCE_CODE_VERIFIER =\n" +
            "    LOCAL_STORAGE_PREFIX + \"code_verifier\";\n" +
            "\n" +
            "  /**\n" +
            "   * Returns all compatibility problems or null.\n" +
            "   * @returns The detected compatibility problems.\n" +
            "   */\n" +
            "  function getBrowserCompatibilityProblemsOrNull() {\n" +
            "    let errorStrings = null;\n" +
            "\n" +
            "    if (!window.localStorage) {\n" +
            "      errorStrings = \"Unable to access local storage API.\";\n" +
            "    }\n" +
            "\n" +
            "    if (!window.crypto) {\n" +
            "      if (errorStrings !== null) {\n" +
            "        errorStrings += \"\\n\";\n" +
            "      } else {\n" +
            "        errorStrings = \"\";\n" +
            "      }\n" +
            "\n" +
            "      errorStrings += \"Unable to access crypto API.\";\n" +
            "    }\n" +
            "\n" +
            "    return errorStrings;\n" +
            "  }\n" +
            "\n" +
            "  /**\n" +
            "   * Creates the authorization URL and performs a redirect.\n" +
            "   * @param {string} clientId The client ID.\n" +
            "   * @param {string} redirectUri The redirect URI.\n" +
            "   * @param {string} authorizationEndpoint The authorization endpoint.\n" +
            "   * @param {string} requestedScopes The requested scopes (separated by whitespace).\n" +
            "   * @param {string} optionalQueryParametersString Optional query parameters.\n" +
            "   */\n" +
            "  async function performSso(\n" +
            "    clientId,\n" +
            "    redirectUri,\n" +
            "    authorizationEndpoint,\n" +
            "    requestedScopes,\n" +
            "    optionalQueryParametersString,\n" +
            "  ) {\n" +
            "    //Redirect to the authorization server.\n" +
            "    window.location = await createSsoUrl(\n" +
            "      clientId,\n" +
            "      redirectUri,\n" +
            "      authorizationEndpoint,\n" +
            "      requestedScopes,\n" +
            "      optionalQueryParametersString,\n" +
            "    );\n" +
            "  }\n" +
            "\n" +
            "  /**\n" +
            "   * Returns true if a SSO response is present, based on the query parameters \"code\" and \"error\".\n" +
            "   * @returns True if a response is present (an expected query parameter is present).\n" +
            "   */\n" +
            "  function isSsoResponsePresent() {\n" +
            "    const searchParams = new URLSearchParams(window.location.search);\n" +
            "\n" +
            "    return searchParams.has(\"code\") || searchParams.has(\"error\");\n" +
            "  }\n" +
            "\n" +
            "  /**\n" +
            "   * Tries to process the SSO request, if the query parameter \"code\" is present. Fails if the query parameter \"error\" is present.\n" +
            "   * If no matching query parameter is present \"null\" is returned. Otherwise the token response JSON object is returned.\n" +
            "   * @param {string} clientId The client ID.\n" +
            "   * @param {string} redirectEndpoint The redirect URI.\n" +
            "   * @param {string} tokenEndpoint The token endpoint.\n" +
            "   * @returns The promise containing the access token data.\n" +
            "   */\n" +
            "  function processSsoResponseAsync(clientId, redirectEndpoint, tokenEndpoint) {\n" +
            "    const promise = new Promise((resolve, reject) => {\n" +
            "      const searchParams = new URLSearchParams(window.location.search);\n" +
            "\n" +
            "      if (searchParams.has(\"error\")) {\n" +
            "        let errorDescription;\n" +
            "\n" +
            "        if (searchParams.has(\"error_description\")) {\n" +
            "          errorDescription =\n" +
            "            \" Description: \" +\n" +
            "            decodeURIComponent(searchParams.get(\"error_description\"));\n" +
            "        } else {\n" +
            "          errorDescription = \"\";\n" +
            "        }\n" +
            "\n" +
            "        resetStoredData();\n" +
            "\n" +
            "        const errorString = decodeURIComponent(searchParams.get(\"error\"));\n" +
            "\n" +
            "        reject(\n" +
            "          new Error(\n" +
            "            \"An error occurred. Cause: \" + errorString + errorDescription,\n" +
            "          ),\n" +
            "        );\n" +
            "      } else if (searchParams.has(\"code\")) {\n" +
            "        if (searchParams.has(\"state\")) {\n" +
            "          if (\n" +
            "            localStorage.getItem(LOCAL_STORAGE_PKCE_STATE) ===\n" +
            "            searchParams.get(\"state\")\n" +
            "          ) {\n" +
            "            sendFormPostRequestAsync(tokenEndpoint, {\n" +
            "              grant_type: \"authorization_code\",\n" +
            "              code: searchParams.get(\"code\"),\n" +
            "              client_id: clientId,\n" +
            "              redirect_uri: redirectEndpoint,\n" +
            "              code_verifier: localStorage.getItem(\n" +
            "                LOCAL_STORAGE_PKCE_CODE_VERIFIER,\n" +
            "              ),\n" +
            "            })\n" +
            "              .then((body) => {\n" +
            "                resetStoredData();\n" +
            "\n" +
            "                if (body.access_token) {\n" +
            "                  resolve(body);\n" +
            "                } else {\n" +
            "                  reject(\n" +
            "                    new Error(\"Unable to find access token in response body.\"),\n" +
            "                  );\n" +
            "                }\n" +
            "              })\n" +
            "              .catch((error) => {\n" +
            "                resetStoredData();\n" +
            "\n" +
            "                reject(error);\n" +
            "              });\n" +
            "          } else {\n" +
            "            resetStoredData();\n" +
            "\n" +
            "            reject(\n" +
            "              new Error(\n" +
            "                \"The state in the query does not match the stored state.\",\n" +
            "              ),\n" +
            "            );\n" +
            "          }\n" +
            "        } else {\n" +
            "          resetStoredData();\n" +
            "\n" +
            "          reject(new Error(\"Unable to find state in query, despite set code.\"));\n" +
            "        }\n" +
            "      } else {\n" +
            "        resolve(null);\n" +
            "      }\n" +
            "    });\n" +
            "\n" +
            "    return promise;\n" +
            "  }\n" +
            "\n" +
            "  /**\n" +
            "   * Creates the authorization URL.\n" +
            "   * @param {string} clientId The client ID.\n" +
            "   * @param {string} redirectUri The redirect URI.\n" +
            "   * @param {string} authorizationEndpoint The authorization endpoint.\n" +
            "   * @param {string} requestedScopes The requested scopes (separated by whitespace).\n" +
            "   * @param {string} optionalQueryParametersString Optional query parameters.\n" +
            "   */\n" +
            "  async function createSsoUrl(\n" +
            "    clientId,\n" +
            "    redirectUri,\n" +
            "    authorizationEndpoint,\n" +
            "    requestedScopes,\n" +
            "    optionalQueryParametersString,\n" +
            "  ) {\n" +
            "    //Create and store a random PKCE state.\n" +
            "\n" +
            "    const pkceStateString = createRandomString();\n" +
            "\n" +
            "    localStorage.setItem(LOCAL_STORAGE_PKCE_STATE, pkceStateString);\n" +
            "\n" +
            "    //Create and store a random PKCE code verifier (the plaintext secret).\n" +
            "\n" +
            "    const codeVerifier = createRandomString();\n" +
            "\n" +
            "    localStorage.setItem(LOCAL_STORAGE_PKCE_CODE_VERIFIER, codeVerifier);\n" +
            "\n" +
            "    //Hash and base64-urlencode the secret to use as the challenge.\n" +
            "\n" +
            "    const codeVerifierTextByteArray = textToByteArray(codeVerifier);\n" +
            "\n" +
            "    const codeVerifierTextHashByteArray = await hashDataWithSha256Async(\n" +
            "      codeVerifierTextByteArray,\n" +
            "    );\n" +
            "\n" +
            "    const codeVerifierTextHashBase64 = urlEncodeCodeVerifierHash(\n" +
            "      codeVerifierTextHashByteArray,\n" +
            "    );\n" +
            "\n" +
            "    //Build the authorization URL.\n" +
            "\n" +
            "    let url =\n" +
            "      authorizationEndpoint +\n" +
            "      \"?response_type=code\" +\n" +
            "      \"&client_id=\" +\n" +
            "      encodeURIComponent(clientId) +\n" +
            "      \"&state=\" +\n" +
            "      encodeURIComponent(pkceStateString) +\n" +
            "      \"&scope=\" +\n" +
            "      encodeURIComponent(requestedScopes) +\n" +
            "      \"&redirect_uri=\" +\n" +
            "      encodeURIComponent(redirectUri) +\n" +
            "      \"&code_challenge=\" +\n" +
            "      encodeURIComponent(codeVerifierTextHashBase64) +\n" +
            "      \"&code_challenge_method=S256\" +\n" +
            "      \"&ui_locales=\" +\n" +
            "      encodeURIComponent(navigator.language);\n" +
            "\n" +
            "    if (\n" +
            "      optionalQueryParametersString &&\n" +
            "      optionalQueryParametersString.trim().length > 0\n" +
            "    ) {\n" +
            "      url += optionalQueryParametersString;\n" +
            "    }\n" +
            "\n" +
            "    return url;\n" +
            "  }\n" +
            "\n" +
            "  /**\n" +
            "   * Creates a cryptographically random string.\n" +
            "   * @param {number} charactersCount Chars count.\n" +
            "   * @returns The created string.\n" +
            "   */\n" +
            "  function createRandomString(charactersCount = 128) {\n" +
            "    //See https://datatracker.ietf.org/doc/html/rfc7636#section-4\n" +
            "\n" +
            "    const characters =\n" +
            "      \"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~\";\n" +
            "    const charactersLength = characters.length;\n" +
            "\n" +
            "    const randomValues = new Uint32Array(charactersCount);\n" +
            "    window.crypto.getRandomValues(randomValues);\n" +
            "\n" +
            "    let resultString = \"\";\n" +
            "\n" +
            "    for (let tmpIndex = 0; tmpIndex < charactersCount; tmpIndex++) {\n" +
            "      const tmpRandomIndex = randomValues[tmpIndex] % charactersLength;\n" +
            "      resultString += characters.charAt(tmpRandomIndex);\n" +
            "    }\n" +
            "\n" +
            "    return resultString;\n" +
            "  }\n" +
            "\n" +
            "  /**\n" +
            "   * Converts a string to a byte array.\n" +
            "   * @param {string} textToHash The string to convert.\n" +
            "   * @returns The byte array representation.\n" +
            "   */\n" +
            "  function textToByteArray(textToHash) {\n" +
            "    const textEncoder = new TextEncoder();\n" +
            "    const encodedTextByteArray = textEncoder.encode(textToHash);\n" +
            "\n" +
            "    return encodedTextByteArray;\n" +
            "  }\n" +
            "\n" +
            "  /**\n" +
            "   * Creates a SHA256 hash.\n" +
            "   * @param {Uint8Array} dataToHash The data to hash.\n" +
            "   * @returns The created hash.\n" +
            "   */\n" +
            "  function hashDataWithSha256Async(dataToHash) {\n" +
            "    // Replaced window.crypto.subtle.digest:\n" +
            "    return sha256DigestFallback(\"SHA-256\", dataToHash);\n" +
            "  }\n" +
            "\n" +
            "  /**\n" +
            "   * URL encodes a string.\n" +
            "   * @param {Uint8Array} arrayToEncode The array to encode.\n" +
            "   * @returns The encoded string.\n" +
            "   */\n" +
            "  function urlEncodeCodeVerifierHash(arrayToEncode) {\n" +
            "    return btoa(String.fromCharCode.apply(null, new Uint8Array(arrayToEncode)))\n" +
            "      .replace(/\\+/g, \"-\")\n" +
            "      .replace(/\\//g, \"_\")\n" +
            "      .replace(/=+$/, \"\");\n" +
            "  }\n" +
            "\n" +
            "  /**\n" +
            "   * Resets all stored data, including the current set history state (URL).\n" +
            "   */\n" +
            "  function resetStoredData() {\n" +
            "    window.history.replaceState(\n" +
            "      null,\n" +
            "      null,\n" +
            "      window.location.origin + window.location.pathname,\n" +
            "    );\n" +
            "\n" +
            "    localStorage.removeItem(LOCAL_STORAGE_PKCE_STATE);\n" +
            "    localStorage.removeItem(LOCAL_STORAGE_PKCE_CODE_VERIFIER);\n" +
            "  }\n" +
            "\n" +
            "  /**\n" +
            "   * Performs a HTTP POST request, with an excpected 200 OK status code, to obtain the response body (a JSON object).\n" +
            "   * @param {string} url The URL to post to.\n" +
            "   * @param {string} contentType The content type of the request (optional).\n" +
            "   * @param {object} keyValueParameters Object as key value body parameters (optional).\n" +
            "   * @param {object} keyValueHeaders Object as key value header parameters (optional).\n" +
            "   * @returns The response JSON body.\n" +
            "   */\n" +
            "  function sendPostRequestAsync(\n" +
            "    url,\n" +
            "    contentType = null,\n" +
            "    keyValueParameters = null,\n" +
            "    keyValueHeaders = null,\n" +
            "  ) {\n" +
            "    const promise = new Promise((resolve, reject) => {\n" +
            "      const request = new XMLHttpRequest();\n" +
            "\n" +
            "      request.open(\"POST\", url, true);\n" +
            "\n" +
            "      if (contentType !== null) {\n" +
            "        request.setRequestHeader(\"Content-Type\", contentType);\n" +
            "      }\n" +
            "\n" +
            "      if (keyValueHeaders !== null) {\n" +
            "        Object.keys(keyValueHeaders).forEach((tmpKey) => {\n" +
            "          request.setRequestHeader(tmpKey, keyValueHeaders[tmpKey]);\n" +
            "        });\n" +
            "      }\n" +
            "\n" +
            "      request.onload = () => {\n" +
            "        if (request.status === 200) {\n" +
            "          try {\n" +
            "            const responseBody = JSON.parse(request.response);\n" +
            "            resolve(responseBody);\n" +
            "          } catch (error) {\n" +
            "            reject(error);\n" +
            "          }\n" +
            "        } else {\n" +
            "          reject(\n" +
            "            new Error(\n" +
            "              \"Unable to perform successful POST request (received status code \" +\n" +
            "                request.status +\n" +
            "                \").\",\n" +
            "            ),\n" +
            "          );\n" +
            "        }\n" +
            "      };\n" +
            "\n" +
            "      request.onerror = () => {\n" +
            "        reject(new Error(\"Unable to perform POST request.\"));\n" +
            "      };\n" +
            "\n" +
            "      let requestBodyString;\n" +
            "\n" +
            "      if (keyValueParameters !== null) {\n" +
            "        requestBodyString = Object.keys(keyValueParameters)\n" +
            "          .map((tmpKey) => tmpKey + \"=\" + keyValueParameters[tmpKey])\n" +
            "          .join(\"&\");\n" +
            "      } else {\n" +
            "        requestBodyString = \"\";\n" +
            "      }\n" +
            "\n" +
            "      request.send(requestBodyString);\n" +
            "    });\n" +
            "\n" +
            "    return promise;\n" +
            "  }\n" +
            "\n" +
            "  /**\n" +
            "   * Performs a HTTP POST request, with an expected 200 OK status code, to obtain the response body (a JSON object).\n" +
            "   * @param {string} url The URL to post to.\n" +
            "   * @param {object} keyValueParameters Object as key value body parameters (optional).\n" +
            "   * @param {object} keyValueHeaders Object as key value header parameters (optional).\n" +
            "   * @returns The response JSON body.\n" +
            "   */\n" +
            "  function sendFormPostRequestAsync(\n" +
            "    url,\n" +
            "    keyValueParameters = null,\n" +
            "    keyValueHeaders = null,\n" +
            "  ) {\n" +
            "    return sendPostRequestAsync(\n" +
            "      url,\n" +
            "      \"application/x-www-form-urlencoded; charset=UTF-8\",\n" +
            "      keyValueParameters,\n" +
            "      keyValueHeaders,\n" +
            "    );\n" +
            "  }\n" +
            "\n" +
            "  /**\n" +
            "   * Performs a HTTP POST request, with an expected 200 OK status code, to obtain the response body (a JSON object).\n" +
            "   * @param {string} url The URL to post to.\n" +
            "   * @param {object} keyValueParameters Object as key value body parameters (optional).\n" +
            "   * @param {object} keyValueHeaders Object as key value header parameters (optional).\n" +
            "   * @returns The response JSON body.\n" +
            "   */\n" +
            "  function sendJsonPostRequestAsync(\n" +
            "    url,\n" +
            "    keyValueParameters = null,\n" +
            "    keyValueHeaders = null,\n" +
            "  ) {\n" +
            "    return sendPostRequestAsync(\n" +
            "      url,\n" +
            "      keyValueParameters,\n" +
            "      \"application/json; charset=UTF-8\",\n" +
            "      keyValueParameters,\n" +
            "      keyValueHeaders,\n" +
            "    );\n" +
            "  }\n" +
            "\n" +
            "  //----------------------------------------------\n" +
            "  // Actual logic (must be executed always)\n" +
            "  //----------------------------------------------\n" +
            "\n" +
            "  function setFavicon(dataUrl) {\n" +
            "    // Remove all existing favicons.\n" +
            "\n" +
            "    document\n" +
            "      .querySelectorAll(\n" +
            "        \"link[rel='icon'], link[rel='shortcut icon'], link[rel='apple-touch-icon']\",\n" +
            "      )\n" +
            "      .forEach((tmpElement) => tmpElement.parentNode.removeChild(tmpElement));\n" +
            "\n" +
            "    // Create new favicon link.\n" +
            "\n" +
            "    const link = document.createElement(\"link\");\n" +
            "\n" +
            "    link.rel = \"icon\";\n" +
            "    link.href = dataUrl;\n" +
            "\n" +
            "    document.head.appendChild(link);\n" +
            "  }\n" +
            "\n" +
            "  const logoSvg =\n" +
            "    \"data:image/svg+xml,%3csvg%20version='1.2'%20xmlns='http://www.w3.org/2000/svg'%20viewBox='0%200%201594%201435'%20width='1594'%20height='1435'%3e%3cpath%20fill='%236800d2'%20id='Layer'%20fill-rule='evenodd'%20class='s0'%20d='m1195.9%2030.4c99.3%2058.6%20133.2%20185%2074.5%20284.3-58.7%2099.3-185%20133.1-284.3%2074.4-99.3-58.6-133.2-185-74.5-284.3%2058.7-99.2%20185-133.1%20284.3-74.4zm-988.3%20893.5c-114.8%200-207.6-92.8-207.6-207.6%200-114.8%2092.8-207.6%20207.6-207.6%20114.8%200%20207.6%2092.8%20207.6%20207.6%200%20114.8-92.8%20207.6-207.6%20207.6zm194.1-898c101.5-54.2%20227.9-18.1%20282%2083.4%2054.2%20101.6%2018.1%20227.9-83.5%20282.1-101.5%2054.1-227.9%2018-282-83.5-54.2-101.5-18.1-227.9%2083.5-282zm787.5%201383.1c-101.6%2054.1-227.9%2018-282.1-83.5-54.2-101.5-18.1-227.9%2083.5-282%20101.5-54.2%20227.9-18.1%20282%2083.4%2056.5%20101.6%2018.1%20225.7-83.4%20282.1zm-794.3-4.5c-99.3-58.7-133.1-185-74.5-284.3%2058.7-99.3%20185-133.1%20284.3-74.5%2099.3%2058.7%20133.2%20185%2074.5%20284.3-56.4%2099.3-185%20133.1-284.3%2074.5zm843.9-834.9c36.1-38.3%2090.3-60.9%20146.7-60.9%20115.1%200%20207.6%2092.5%20207.6%20207.6%200%20115.1-92.5%20207.6-207.6%20207.6-56.4%200-108.3-22.6-146.7-60.9-103.8-103.8-191.8-103.8-295.6%200-36.1%2038.3-90.3%2060.9-146.7%2060.9-115%200-207.6-92.5-207.6-207.6%200-115.1%2092.6-207.6%20207.6-207.6%2056.4%200%20108.3%2022.6%20146.7%2060.9%20103.8%20103.8%20191.8%20103.8%20295.6%200z'/%3e%3c/svg%3e\";\n" +
            "\n" +
            "  setFavicon(logoSvg);\n" +
            "\n" +
            "  // Find table to mofify or fail.\n" +
            "\n" +
            "  const tableElement = document.querySelector(\n" +
            "    \"div.v-formlayout-login-form > table\",\n" +
            "  );\n" +
            "\n" +
            "  if (tableElement) {\n" +
            "    // Modify DOM.\n" +
            "\n" +
            "    tableElement.style.display = \"none\";\n" +
            "\n" +
            "    const formElement = document.querySelector(\"div.v-formlayout-login-form\");\n" +
            "    formElement.style.fontFamily = \"Mulish, Helvetica, sans-serif\";\n" +
            "\n" +
            "    const logoElement = document.createElement(\"img\");\n" +
            "    logoElement.style = \"width: 7em; margin-left: 5.5em; margin-top: 1em;\";\n" +
            "    logoElement.src = logoSvg;\n" +
            "\n" +
            "    formElement.appendChild(logoElement);\n" +
            "\n" +
            "    formElement.appendChild(document.createElement(\"br\"));\n" +
            "\n" +
            "    const btnOauthLoginSubmitElement = document.createElement(\"button\");\n" +
            "    btnOauthLoginSubmitElement.innerText = \"Login with Gamma-Account SSO\";\n" +
            "    btnOauthLoginSubmitElement.style =\n" +
            "      \"background-color: #6800d2; color: #fff; border-radius: 2em; margin: 2em; padding-left: 1.2em; padding-right: 1.2em; padding-top: 0.2em; padding-bottom: 0.2em; width: 14em; cursor: pointer;\";\n" +
            "\n" +
            "    formElement.appendChild(btnOauthLoginSubmitElement);\n" +
            "\n" +
            "    // Do SSO stuff (prepare or submit SSO data).\n" +
            "\n" +
            "    //SSO configuration.\n" +
            "\n" +
            "    let oauthConfig;\n" +
            "\n" +
            "    if (!location.hostname.includes(\"qs\")) {\n" +
            "      //Set the prod configuration.\n" +
            "\n" +
            "      oauthConfig = {\n" +
            "        clientId: \"de.gammacommunications.magic-control-panel\",\n" +
            "        redirectPathSuffix: \"/ui\",\n" +
            "        authorizationEndpoint:\n" +
            "          \"https://login.gamma-portal.com/realms/europe/protocol/openid-connect/auth\",\n" +
            "        requestedScopes: \"openid email\",\n" +
            "        tokenEndpoint:\n" +
            "          \"https://login.gamma-portal.com/realms/europe/protocol/openid-connect/token\",\n" +
            "      };\n" +
            "    } else {\n" +
            "      //Set the QS configuration.\n" +
            "\n" +
            "      oauthConfig = {\n" +
            "        clientId: \"de.gammacommunications.magic-control-panel\",\n" +
            "        redirectPathSuffix: \"/ui\",\n" +
            "        authorizationEndpoint:\n" +
            "          \"https://login-lab.gamma-portal.com/realms/dev-europe/protocol/openid-connect/auth\",\n" +
            "        requestedScopes: \"openid email\",\n" +
            "        tokenEndpoint:\n" +
            "          \"https://login-lab.gamma-portal.com/realms/dev-europe/protocol/openid-connect/token\",\n" +
            "      };\n" +
            "    }\n" +
            "\n" +
            "    //Username which is used during SSO.\n" +
            "\n" +
            "    const AUTH_TYPE_KEYCLOAK_ACCESS_TOKEN_PREFIX =\n" +
            "      \"AUTH_TYPE_KEYCLOAK_ACCESS_TOKEN;\";\n" +
            "\n" +
            "    //Find all DOM elements.\n" +
            "\n" +
            "    const regularUsernameFieldElement = document.querySelector(\n" +
            "      'td > input[type=\"text\"]',\n" +
            "    );\n" +
            "\n" +
            "    const regularPasswordFieldElement = document.querySelector(\n" +
            "      'td > input[type=\"password\"]',\n" +
            "    );\n" +
            "\n" +
            "    const regularButtonLoginSubmitElement = document.querySelector(\n" +
            "      \"div.v-button.v-widget\",\n" +
            "    );\n" +
            "\n" +
            "    //Create port string if set.\n" +
            "\n" +
            "    let portString = \"\";\n" +
            "\n" +
            "    if (location.port !== \"\") {\n" +
            "      portString = \":\" + location.port;\n" +
            "    }\n" +
            "\n" +
            "    //Show SSO login button only if the browser is compatible.\n" +
            "\n" +
            "    const compatibilityProblems = getBrowserCompatibilityProblemsOrNull();\n" +
            "\n" +
            "    if (compatibilityProblems !== null) {\n" +
            "      console.error(\"Unable to enable SSO login. Cause:\");\n" +
            "      console.error(compatibilityProblems);\n" +
            "\n" +
            "      btnOauthLoginSubmitElement.style.display = \"none\";\n" +
            "      return;\n" +
            "    }\n" +
            "\n" +
            "    //DOM logic.\n" +
            "\n" +
            "    btnOauthLoginSubmitElement.addEventListener(\"click\", (event) => {\n" +
            "      //Always cancel the form POST!\n" +
            "      event.preventDefault();\n" +
            "\n" +
            "      //Triggers the initial PKCE SSO request.\n" +
            "      const ssoRedirectUrl =\n" +
            "        location.protocol +\n" +
            "        \"//\" +\n" +
            "        location.hostname +\n" +
            "        portString +\n" +
            "        oauthConfig.redirectPathSuffix;\n" +
            "\n" +
            "      performSso(\n" +
            "        oauthConfig.clientId,\n" +
            "        ssoRedirectUrl,\n" +
            "        oauthConfig.authorizationEndpoint,\n" +
            "        oauthConfig.requestedScopes,\n" +
            "      );\n" +
            "    });\n" +
            "\n" +
            "    //The following logic checks the current URL for query parameters from the SSO redirect.\n" +
            "\n" +
            "    if (isSsoResponsePresent()) {\n" +
            "      //Adjust waiting view.\n" +
            "\n" +
            "      btnOauthLoginSubmitElement.disabled = \"true\";\n" +
            "\n" +
            "      //Process SSO response.\n" +
            "\n" +
            "      const ssoRedirectUrl =\n" +
            "        location.protocol +\n" +
            "        \"//\" +\n" +
            "        location.hostname +\n" +
            "        portString +\n" +
            "        oauthConfig.redirectPathSuffix;\n" +
            "\n" +
            "      processSsoResponseAsync(\n" +
            "        oauthConfig.clientId,\n" +
            "        ssoRedirectUrl,\n" +
            "        oauthConfig.tokenEndpoint,\n" +
            "      )\n" +
            "        .then((response) => {\n" +
            "          sessionStorage.setItem(\"idToken\", response.id_token);\n" +
            "\n" +
            "          console.debug(\"Try to extract user-ID claim.\");\n" +
            "\n" +
            "          readCustomClaim(\n" +
            "            response.access_token,\n" +
            "            \"de.gammacommunications.user-id\",\n" +
            "          )\n" +
            "            .then((userIdClaim) => {\n" +
            "              console.debug(`Extracted user-ID claim: ${userIdClaim}`);\n" +
            "              console.debug(\"Try to feed credentials into DOM elements.\");\n" +
            "\n" +
            "              const usernamePromise = simulateInteraction(\n" +
            "                regularUsernameFieldElement,\n" +
            "                userIdClaim,\n" +
            "              );\n" +
            "\n" +
            "              // We must include the trigger inside the password field, to avoid lookup-errors,\n" +
            "              // before the authenticaiton-logic runs.\n" +
            "              const passwordClaim = AUTH_TYPE_KEYCLOAK_ACCESS_TOKEN_PREFIX + response.access_token;\n" +
            "\n" +
            "              const passwordPromise = simulateInteraction(\n" +
            "                regularPasswordFieldElement,\n" +
            "                passwordClaim,\n" +
            "              );\n" +
            "\n" +
            "              Promise.all([usernamePromise, passwordPromise])\n" +
            "                .then(() => {\n" +
            "                  console.debug(\"Try to submit credentials.\");\n" +
            "\n" +
            "                  regularButtonLoginSubmitElement.click();\n" +
            "                })\n" +
            "                .catch((error) => {\n" +
            "                  console.error(\n" +
            "                    \"Unable to feed credentials into DOM elements: \",\n" +
            "                  );\n" +
            "                  console.error(error);\n" +
            "\n" +
            "                  alert(\n" +
            "                    \"Unable to submit credentials. Please try again. If the problem persists, please contact support.\",\n" +
            "                  );\n" +
            "\n" +
            "                  btnOauthLoginSubmitElement.disabled = \"\";\n" +
            "                });\n" +
            "            })\n" +
            "            .catch((error) => {\n" +
            "              console.error(\"Unable to extract user-claim: \");\n" +
            "              console.error(error);\n" +
            "\n" +
            "              alert(\n" +
            "                \"Unable to extract user-claim. Please try again or use a different user. If the problem persists, please contact support.\",\n" +
            "              );\n" +
            "\n" +
            "              btnOauthLoginSubmitElement.disabled = \"\";\n" +
            "            });\n" +
            "        })\n" +
            "        .catch((error) => {\n" +
            "          console.error(\"An error occurred: \");\n" +
            "          console.error(error);\n" +
            "\n" +
            "          alert(\n" +
            "            \"Access token could not be retrieved. Please try again. If the problem persists, please contact support.\",\n" +
            "          );\n" +
            "\n" +
            "          btnOauthLoginSubmitElement.disabled = \"\";\n" +
            "        });\n" +
            "    } else {\n" +
            "      console.log(\"No SSO response is present.\");\n" +
            "    }\n" +
            "  } else {\n" +
            "    console.error(\"Unable to find login-form table! Show legacy login...\");\n" +
            "  }\n" +
            "})();\n";
}
