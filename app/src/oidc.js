// Thin wrapper around openid-client v6: Authorization Code + PKCE (S256),
// state and nonce checks, and RP-initiated logout.
import * as client from 'openid-client';

export async function createOidc(config) {
  // openid-client refuses plain-HTTP issuers unless explicitly allowed.
  // config.js only permits http for localhost, so this is dev-only.
  const options = config.allowInsecureIssuer
    ? { execute: [client.allowInsecureRequests] }
    : undefined;

  // Public client: no client secret, authenticates with PKCE only.
  const oidcConfig = await client.discovery(
    config.issuer,
    config.clientId,
    undefined,
    client.None(),
    options,
  );

  return {
    /** Builds the authorization URL and the values that must be kept in the session. */
    async startLogin() {
      const codeVerifier = client.randomPKCECodeVerifier();
      const codeChallenge = await client.calculatePKCECodeChallenge(codeVerifier);
      const state = client.randomState();
      const nonce = client.randomNonce();
      const url = client.buildAuthorizationUrl(oidcConfig, {
        redirect_uri: config.redirectUri,
        scope: 'openid profile email',
        code_challenge: codeChallenge,
        code_challenge_method: 'S256',
        state,
        nonce,
      });
      return { url, transaction: { codeVerifier, state, nonce } };
    },

    /** Exchanges the code; throws if state, nonce, PKCE or the ID token signature don't check out. */
    async finishLogin(currentUrl, transaction) {
      const tokens = await client.authorizationCodeGrant(oidcConfig, currentUrl, {
        pkceCodeVerifier: transaction.codeVerifier,
        expectedState: transaction.state,
        expectedNonce: transaction.nonce,
        idTokenExpected: true,
      });
      return { claims: tokens.claims(), idToken: tokens.id_token };
    },

    /** RP-initiated logout URL at the provider's end_session_endpoint, or null if unsupported. */
    logoutUrl(idToken) {
      if (!oidcConfig.serverMetadata().end_session_endpoint) return null;
      const params = {
        client_id: config.clientId,
        post_logout_redirect_uri: config.postLogoutRedirectUri,
      };
      if (idToken) params.id_token_hint = idToken;
      return client.buildEndSessionUrl(oidcConfig, params).href;
    },
  };
}
