import { AuthException } from 'src/engine/core-modules/auth/auth.exception';
import {
  getPlatformOidcSettings,
  getPlatformOidcClient,
} from 'src/engine/core-modules/auth/platform-oidc/platform-oidc.config';
import { validatePlatformOidcClaims } from 'src/engine/core-modules/auth/platform-oidc/platform-oidc.auth.strategy';

const ENV_KEYS = [
  'PLATFORM_OIDC_ISSUER',
  'PLATFORM_OIDC_CLIENT_ID',
  'PLATFORM_OIDC_CLIENT_SECRET',
  'PLATFORM_OIDC_TENANT_ID',
  'SERVER_URL',
] as const;

const ORIGINAL_ENV: Record<string, string | undefined> = {};

const setAllEnv = (overrides: Partial<Record<string, string>> = {}) => {
  process.env.PLATFORM_OIDC_ISSUER = 'https://broker.example.com/oidc';
  process.env.PLATFORM_OIDC_CLIENT_ID = 'client-id';
  process.env.PLATFORM_OIDC_CLIENT_SECRET = 'client-secret';
  process.env.PLATFORM_OIDC_TENANT_ID = 'tenant-abc';
  process.env.SERVER_URL = 'https://tenant1.crm.example.com';
  Object.assign(process.env, overrides);
};

describe('validatePlatformOidcClaims', () => {
  const tenantId = 'tenant-abc';

  const baseClaims = () => ({
    tenant_id: tenantId,
    modules: ['crm'],
    email_verified: true,
    email: 'A@x.com',
    name: 'Ann Lee',
    principal_type: 'owner',
    sub: 's',
  });

  it('returns the mapped user for valid owner claims', () => {
    const result = validatePlatformOidcClaims(baseClaims(), tenantId);

    expect(result).toEqual({
      email: 'a@x.com',
      firstName: 'Ann',
      lastName: 'Lee',
      principalType: 'owner',
      subject: 's',
    });
  });

  it('returns the mapped user for valid staff claims', () => {
    const result = validatePlatformOidcClaims(
      { ...baseClaims(), principal_type: 'staff' },
      tenantId,
    );

    expect(result.principalType).toBe('staff');
  });

  it('throws AuthException when tenant_id differs', () => {
    expect(() =>
      validatePlatformOidcClaims(
        { ...baseClaims(), tenant_id: 'other-tenant' },
        tenantId,
      ),
    ).toThrow(AuthException);
  });

  it('throws AuthException when modules is missing', () => {
    const claims = baseClaims() as Record<string, unknown>;

    delete claims.modules;

    expect(() => validatePlatformOidcClaims(claims, tenantId)).toThrow(
      AuthException,
    );
  });

  it('throws AuthException when modules is not an array', () => {
    expect(() =>
      validatePlatformOidcClaims(
        { ...baseClaims(), modules: 'crm' },
        tenantId,
      ),
    ).toThrow(AuthException);
  });

  it('throws AuthException when modules lacks "crm"', () => {
    expect(() =>
      validatePlatformOidcClaims(
        { ...baseClaims(), modules: ['scheduling'] },
        tenantId,
      ),
    ).toThrow(AuthException);
  });

  it('throws AuthException when email_verified is not exactly true', () => {
    expect(() =>
      validatePlatformOidcClaims(
        { ...baseClaims(), email_verified: 'true' },
        tenantId,
      ),
    ).toThrow(AuthException);
  });

  it('throws AuthException when email is not a string', () => {
    expect(() =>
      validatePlatformOidcClaims({ ...baseClaims(), email: 123 }, tenantId),
    ).toThrow(AuthException);
  });

  it('throws AuthException when principal_type is not "owner"/"staff"', () => {
    expect(() =>
      validatePlatformOidcClaims(
        { ...baseClaims(), principal_type: 'admin' },
        tenantId,
      ),
    ).toThrow(AuthException);
  });

  it('falls back firstName to the email local-part and lastName to "" when name is missing', () => {
    const claims = baseClaims() as Record<string, unknown>;

    delete claims.name;

    const result = validatePlatformOidcClaims(claims, tenantId);

    expect(result.firstName).toBe('a');
    expect(result.lastName).toBe('');
  });
});

describe('getPlatformOidcSettings', () => {
  beforeEach(() => {
    for (const key of ENV_KEYS) {
      ORIGINAL_ENV[key] = process.env[key];
      delete process.env[key];
    }
  });

  afterEach(() => {
    for (const key of ENV_KEYS) {
      if (ORIGINAL_ENV[key] === undefined) {
        delete process.env[key];
      } else {
        process.env[key] = ORIGINAL_ENV[key];
      }
    }
  });

  it('returns null when PLATFORM_OIDC_ISSUER is empty', () => {
    setAllEnv({ PLATFORM_OIDC_ISSUER: '' });

    expect(getPlatformOidcSettings()).toBeNull();
  });

  it('returns null when PLATFORM_OIDC_CLIENT_ID is empty', () => {
    setAllEnv({ PLATFORM_OIDC_CLIENT_ID: '' });

    expect(getPlatformOidcSettings()).toBeNull();
  });

  it('returns null when PLATFORM_OIDC_CLIENT_SECRET is empty', () => {
    setAllEnv({ PLATFORM_OIDC_CLIENT_SECRET: '' });

    expect(getPlatformOidcSettings()).toBeNull();
  });

  it('returns null when PLATFORM_OIDC_TENANT_ID is empty', () => {
    setAllEnv({ PLATFORM_OIDC_TENANT_ID: '' });

    expect(getPlatformOidcSettings()).toBeNull();
  });

  it('returns null when SERVER_URL is empty', () => {
    setAllEnv({ SERVER_URL: '' });

    expect(getPlatformOidcSettings()).toBeNull();
  });

  it('builds callbackUrl as SERVER_URL without trailing slash + /auth/platform-oidc/callback', () => {
    setAllEnv({ SERVER_URL: 'https://tenant1.crm.example.com/' });

    const settings = getPlatformOidcSettings();

    expect(settings).not.toBeNull();
    expect(settings?.callbackUrl).toBe(
      'https://tenant1.crm.example.com/auth/platform-oidc/callback',
    );
  });

  it('returns the full settings object when every env var is present', () => {
    setAllEnv();

    expect(getPlatformOidcSettings()).toEqual({
      issuer: 'https://broker.example.com/oidc',
      clientId: 'client-id',
      clientSecret: 'client-secret',
      tenantId: 'tenant-abc',
      callbackUrl: 'https://tenant1.crm.example.com/auth/platform-oidc/callback',
    });
  });
});

describe('getPlatformOidcClient', () => {
  beforeEach(() => {
    for (const key of ENV_KEYS) {
      ORIGINAL_ENV[key] = process.env[key];
      delete process.env[key];
    }
  });

  afterEach(() => {
    for (const key of ENV_KEYS) {
      if (ORIGINAL_ENV[key] === undefined) {
        delete process.env[key];
      } else {
        process.env[key] = ORIGINAL_ENV[key];
      }
    }
  });

  it('rejects when settings are not configured', async () => {
    for (const key of ENV_KEYS) {
      delete process.env[key];
    }

    await expect(getPlatformOidcClient()).rejects.toThrow(
      'Platform OIDC settings are not configured',
    );
  });
});
