import { Issuer, type Client } from 'openid-client';

// Clean-room AGPL code (carries no commercial-license header) written from
// openid-client's public API, not from any of Twenty's commercially
// licensed OIDC files (D-01/D-02, Phase 26 plan 05). These five vars are read directly from
// process.env rather than added to twenty-config's typed config-variables
// file — adding them there would be a second core edit beyond auth.module.ts,
// which D-02 scopes this exception to.
export type PlatformOidcSettings = {
  issuer: string;
  clientId: string;
  clientSecret: string;
  tenantId: string;
  callbackUrl: string;
};

export const getPlatformOidcSettings = (): PlatformOidcSettings | null => {
  const issuer = process.env.PLATFORM_OIDC_ISSUER;
  const clientId = process.env.PLATFORM_OIDC_CLIENT_ID;
  const clientSecret = process.env.PLATFORM_OIDC_CLIENT_SECRET;
  const tenantId = process.env.PLATFORM_OIDC_TENANT_ID;
  const serverUrl = process.env.SERVER_URL;

  if (!issuer || !clientId || !clientSecret || !tenantId || !serverUrl) {
    return null;
  }

  const callbackUrl = `${serverUrl.replace(/\/$/, '')}/auth/platform-oidc/callback`;

  return { issuer, clientId, clientSecret, tenantId, callbackUrl };
};

// Cached across requests — Issuer.discover() is a network call to the
// broker's own discovery document. The cache is reset on rejection so a
// transient broker outage doesn't permanently poison every later request.
let clientPromise: Promise<Client> | null = null;

export const getPlatformOidcClient = async (): Promise<Client> => {
  if (!clientPromise) {
    clientPromise = buildPlatformOidcClient().catch((error) => {
      clientPromise = null;
      throw error;
    });
  }

  return clientPromise;
};

const buildPlatformOidcClient = async (): Promise<Client> => {
  const settings = getPlatformOidcSettings();

  if (!settings) {
    throw new Error('Platform OIDC settings are not configured');
  }

  const issuer = await Issuer.discover(settings.issuer);

  return new issuer.Client({
    client_id: settings.clientId,
    client_secret: settings.clientSecret,
    redirect_uris: [settings.callbackUrl],
    response_types: ['code'],
    token_endpoint_auth_method: 'client_secret_basic',
    id_token_signed_response_alg: 'RS256',
  });
};
