import { Injectable } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';

import { type Request } from 'express';
import { Strategy, type Client, type TokenSet } from 'openid-client';

import {
  AuthException,
  AuthExceptionCode,
} from 'src/engine/core-modules/auth/auth.exception';
import { getPlatformOidcSettings } from 'src/engine/core-modules/auth/platform-oidc/platform-oidc.config';

// Clean-room AGPL code (carries no commercial-license header), written from
// openid-client's public API and the OSS google.auth.strategy.ts structural
// pattern (PassportStrategy mixin, validate-and-reject shape) per D-01/D-02
// (Phase 26 plan 05) — never derived from Twenty's commercially licensed
// oidc.auth.strategy.ts, which must not be opened as a reference.
export type PlatformOidcUser = {
  email: string;
  firstName: string;
  lastName: string;
  principalType: 'owner' | 'staff';
  subject: string;
};

export type PlatformOidcRequest = Request & { user: PlatformOidcUser };

export const validatePlatformOidcClaims = (
  claims: Record<string, unknown>,
  expectedTenantId: string,
): PlatformOidcUser => {
  const { tenant_id, modules, email_verified, email, principal_type, sub } =
    claims;

  if (tenant_id !== expectedTenantId) {
    throw new AuthException(
      'Platform OIDC token is not valid for this tenant',
      AuthExceptionCode.FORBIDDEN_EXCEPTION,
    );
  }

  if (!Array.isArray(modules) || !modules.includes('crm')) {
    throw new AuthException(
      'Platform OIDC token does not grant access to this module',
      AuthExceptionCode.FORBIDDEN_EXCEPTION,
    );
  }

  if (email_verified !== true) {
    throw new AuthException(
      'Platform OIDC token email is not verified',
      AuthExceptionCode.FORBIDDEN_EXCEPTION,
    );
  }

  if (typeof email !== 'string' || email.length === 0) {
    throw new AuthException(
      'Platform OIDC token is missing an email claim',
      AuthExceptionCode.FORBIDDEN_EXCEPTION,
    );
  }

  if (principal_type !== 'owner' && principal_type !== 'staff') {
    throw new AuthException(
      'Platform OIDC token has an invalid principal type',
      AuthExceptionCode.FORBIDDEN_EXCEPTION,
    );
  }

  const normalizedEmail = email.toLowerCase();
  const name = typeof claims.name === 'string' ? claims.name : undefined;
  const [firstName, lastName] = name
    ? splitName(name)
    : [normalizedEmail.split('@')[0], ''];

  return {
    email: normalizedEmail,
    firstName,
    lastName,
    principalType: principal_type,
    subject: typeof sub === 'string' ? sub : '',
  };
};

const splitName = (name: string): [string, string] => {
  const [firstName, ...rest] = name.trim().split(/\s+/);

  return [firstName, rest.join(' ')];
};

@Injectable()
export class PlatformOidcAuthStrategy extends PassportStrategy(Strategy, 'platform-oidc') {
  constructor(client: Client) {
    super({
      client,
      params: { scope: 'openid email profile' },
      usePKCE: 'S256',
      passReqToCallback: true,
    });
  }

  // openid-client's Strategy already verifies the ID token's RS256
  // signature against the broker's JWKS, plus iss, aud (= this client's own
  // client_id), exp, and the PKCE/state round trip — none of that is
  // reimplemented here. This callback only adds the tenant + module gate
  // (validatePlatformOidcClaims). Deliberately takes (req, tokenSet) only —
  // no accessToken/refreshToken/userinfo params — so openid-client never
  // calls a userinfo endpoint; the broker exposes none (26-01-SUMMARY.md).
  async validate(
    _req: Request,
    tokenSet: TokenSet,
  ): Promise<PlatformOidcUser> {
    const settings = getPlatformOidcSettings();

    if (!settings) {
      throw new AuthException(
        'Platform OIDC is not configured',
        AuthExceptionCode.INVALID_INPUT,
      );
    }

    return validatePlatformOidcClaims(tokenSet.claims(), settings.tenantId);
  }
}
