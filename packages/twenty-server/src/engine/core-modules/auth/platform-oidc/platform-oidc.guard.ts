import { type ExecutionContext, Injectable } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';

import { type Request } from 'express';

import {
  AuthException,
  AuthExceptionCode,
} from 'src/engine/core-modules/auth/auth.exception';
import { GuardRedirectService } from 'src/engine/core-modules/guard-redirect/services/guard-redirect.service';

// Clean-room AGPL code, structural mirror of google-oauth.guard.ts's
// try/catch-around-super.canActivate + access_denied mapping, scoped to
// 'platform-oidc' per D-01/D-02. No workspace lookup is needed here (unlike
// Google's guard) — this tenant's Twenty instance has exactly one workspace
// at most (Phase 24 D-01: one container per tenant), resolved later inside
// PlatformOidcAuthService, not from a client-supplied workspaceId.
@Injectable()
export class PlatformOidcGuard extends AuthGuard('platform-oidc') {
  constructor(private readonly guardRedirectService: GuardRedirectService) {
    super();
  }

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest<Request>();

    try {
      if (request.query.error === 'access_denied') {
        throw new AuthException(
          'Platform SSO access denied',
          AuthExceptionCode.OAUTH_ACCESS_DENIED,
        );
      }

      return (await super.canActivate(context)) as boolean;
    } catch (err) {
      this.guardRedirectService.dispatchErrorFromGuard(
        context,
        err,
        this.guardRedirectService.getSubdomainAndCustomDomainFromContext(
          context,
        ),
      );

      return false;
    }
  }
}
