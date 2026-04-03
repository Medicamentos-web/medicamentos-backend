/**
 * passport-apple devuelve callback(null, undefined, ...) cuando Apple responde JSON
 * con { error, error_description } sin access_token; passport-oauth2 entonces genera
 * solo "Failed to obtain access token" y se pierde el motivo real.
 * Reemplaza getOAuthAccessToken con una versión que propaga el error de Apple.
 */
const querystring = require("querystring");
const AppleClientSecret = require("passport-apple/src/token");

/**
 * @param {*} appleStrategy - instancia de AppleStrategy (passport-apple)
 * @param {{ clientID: string, teamID: string, keyID: string, privateKeyString?: string, privateKeyLocation?: string }} opts
 */
function patchAppleOAuthAccessToken(appleStrategy, opts) {
  const _tokenGenerator = new AppleClientSecret(
    {
      client_id: opts.clientID,
      team_id: opts.teamID,
      key_id: opts.keyID,
    },
    opts.privateKeyLocation,
    opts.privateKeyString
  );

  appleStrategy._oauth2.getOAuthAccessToken = function (code, params, callback) {
    _tokenGenerator
      .generate()
      .then((client_secret) => {
        params = params || {};
        if (!params.redirect_uri && appleStrategy._callbackURL) {
          params.redirect_uri = appleStrategy._callbackURL;
        }
        const codeParam = params.grant_type === "refresh_token" ? "refresh_token" : "code";
        params[codeParam] = code;
        params.client_id = this._clientId;
        params.client_secret = client_secret;

        const post_data = querystring.stringify(params);
        const post_headers = { "Content-Type": "application/x-www-form-urlencoded" };
        this._request(
          "POST",
          this._getAccessTokenUrl(),
          post_headers,
          post_data,
          null,
          function (error, data, _response) {
            // node-oauth devuelve { statusCode, data } en 4xx/5xx; el JSON de Apple va en data.
            // Si pasamos ese objeto tal cual, passport-oauth2 envuelve InternalOAuthError sin .message útil.
            if (error) {
              if (error.statusCode != null && error.data != null) {
                const raw = error.data;
                const rawStr = Buffer.isBuffer(raw) ? raw.toString("utf8") : String(raw);
                try {
                  const p = JSON.parse(rawStr);
                  if (p && p.error) {
                    const msg = p.error_description || p.error;
                    callback(new Error(`Apple token: ${msg}`));
                    return;
                  }
                } catch (_) {
                  /* seguir */
                }
                callback(
                  new Error(`Apple token: HTTP ${error.statusCode} ${rawStr.slice(0, 300)}`)
                );
                return;
              }
              callback(error);
              return;
            }
            let results;
            try {
              const dataStr = Buffer.isBuffer(data) ? data.toString("utf8") : String(data || "");
              results = JSON.parse(dataStr);
            } catch (e) {
              callback(
                new Error(
                  `Apple token: respuesta no JSON (${String(data || "").slice(0, 400)})`
                )
              );
              return;
            }
            if (results.error) {
              const msg = results.error_description || results.error;
              callback(new Error(`Apple token: ${msg}`));
              return;
            }
            const refresh_token = results.refresh_token;
            // Apple a veces omite access_token pero envía id_token; passport-oauth2 exige un accessToken truthy.
            const access_token = results.access_token || results.id_token;
            if (!access_token) {
              callback(
                new Error(`Apple token: sin access_token ni id_token (${JSON.stringify(results).slice(0, 500)})`)
              );
              return;
            }
            callback(null, access_token, refresh_token, results.id_token);
          }
        );
      })
      .catch((error) => {
        callback(error);
      });
  };
}

module.exports = { patchAppleOAuthAccessToken };
