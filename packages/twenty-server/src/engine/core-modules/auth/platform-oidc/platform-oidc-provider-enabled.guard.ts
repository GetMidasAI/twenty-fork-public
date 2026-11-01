import { type CanActivate, type ExecutionContext, Injectable } from '@nestjs/common';

import {
  AuthException,
  AuthExceptionCode,
} from 'src/engine/core-modules/auth/auth.exception';
import {
  getPlatformOidcClient,
  getPlatformOidcSettings,
} from 'src/engine/core-modules/auth/platform-oidc/platform-oidc.config';
import { PlatformOidcAuthStrategy } from 'src/engine/core-modules/auth/platform-oidc/platform-oidc.auth.strategy';
import { GuardRedirectService } from 'src/engine/core-modules/guard-redirect/services/guard-redirect.service';

// Clean-room AGPL code, structural mirror of google-provider-enabled.guard.ts
// (lazy strategy construction so passport's 'platform-oidc' strategy is only
// registered on a request that actually reaches this guard) per D-01/D-02.
@Injectable()
export class PlatformOidcProviderEnabledGuard implements CanActivate {
  constructor(private readonly guardRedirectService: GuardRedirectService) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    try {
      const settings = getPlatformOidcSettings();

      if (!settings) {
        throw new AuthException(
          'Platform SSO is not configured',
          AuthExceptionCode.OAUTH_ACCESS_DENIED,
        );
      }

      new PlatformOidcAuthStrategy(await getPlatformOidcClient());

      return true;
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
