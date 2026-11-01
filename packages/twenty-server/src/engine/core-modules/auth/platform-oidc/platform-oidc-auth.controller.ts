import { Controller, Get, Req, Res, UseFilters, UseGuards } from '@nestjs/common';

import { Response } from 'express';
import { ApiPath } from 'twenty-shared/types';

import { AuthOAuthExceptionFilter } from 'src/engine/core-modules/auth/filters/auth-oauth-exception.filter';
import { AuthRestApiExceptionFilter } from 'src/engine/core-modules/auth/filters/auth-rest-api-exception.filter';
import { PlatformOidcGuard } from 'src/engine/core-modules/auth/platform-oidc/platform-oidc.guard';
import { PlatformOidcProviderEnabledGuard } from 'src/engine/core-modules/auth/platform-oidc/platform-oidc-provider-enabled.guard';
import { PlatformOidcAuthService } from 'src/engine/core-modules/auth/platform-oidc/platform-oidc-auth.service';
import { type PlatformOidcRequest } from 'src/engine/core-modules/auth/platform-oidc/platform-oidc.auth.strategy';
import { NoPermissionGuard } from 'src/engine/guards/no-permission.guard';
import { PublicEndpointGuard } from 'src/engine/guards/public-endpoint.guard';

// Clean-room AGPL code, structural mirror of google-auth.controller.ts per
// D-01/D-02 — GET triggers the broker redirect (via PlatformOidcGuard), GET
// callback completes the handshake and JIT-provisions the user.
@Controller(`${ApiPath.Auth}/platform-oidc`)
@UseFilters(AuthRestApiExceptionFilter)
export class PlatformOidcAuthController {
  constructor(
    private readonly platformOidcAuthService: PlatformOidcAuthService,
  ) {}

  @Get()
  @UseGuards(
    PlatformOidcProviderEnabledGuard,
    PlatformOidcGuard,
    PublicEndpointGuard,
    NoPermissionGuard,
  )
  async platformOidcAuth() {
    // Protected by PlatformOidcGuard, which triggers the redirect to the
    // broker's authorization_endpoint; this method body never runs.
    return;
  }

  @Get('callback')
  @UseGuards(
    PlatformOidcProviderEnabledGuard,
    PlatformOidcGuard,
    PublicEndpointGuard,
    NoPermissionGuard,
  )
  @UseFilters(AuthOAuthExceptionFilter)
  async platformOidcAuthCallback(
    @Req() req: PlatformOidcRequest,
    @Res() res: Response,
  ) {
    return res.redirect(
      await this.platformOidcAuthService.signInUpFromPlatformOidc(req.user),
    );
  }
}
