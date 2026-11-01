import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';

import { Repository } from 'typeorm';
import { AppPath } from 'twenty-shared/types';

import {
  AuthException,
  AuthExceptionCode,
} from 'src/engine/core-modules/auth/auth.exception';
import { type PlatformOidcUser } from 'src/engine/core-modules/auth/platform-oidc/platform-oidc.auth.strategy';
import { AuthService } from 'src/engine/core-modules/auth/services/auth.service';
import { SignInUpService } from 'src/engine/core-modules/auth/services/sign-in-up.service';
import { LoginTokenService } from 'src/engine/core-modules/auth/token/services/login-token.service';
import { WorkspaceDomainsService } from 'src/engine/core-modules/domain/workspace-domains/services/workspace-domains.service';
import { GuardRedirectService } from 'src/engine/core-modules/guard-redirect/services/guard-redirect.service';
import { UserService } from 'src/engine/core-modules/user/services/user.service';
import { AuthProviderEnum } from 'src/engine/core-modules/workspace/types/workspace.type';
import { WorkspaceEntity } from 'src/engine/core-modules/workspace/workspace.entity';

// Clean-room AGPL code (carries no commercial-license header), written for
// Phase 26 plan 05 (D-01/D-02) — JIT sign-in/up from the platform broker's
// verified ID-token claims.
//
// WHY Twenty's own invitation-based access check (the same gate
// signInUpWithSocialSso calls before every sign-in) is never invoked here
// (D-07): the broker's modules[] claim, scoped per staff member at
// token-issuance time, already IS the authorization decision — this RP
// trusts the broker's JIT-provisioning contract instead of re-deriving
// access from Twenty's own invitation/public-invite-link machinery, which
// has no concept of the platform's per-tenant module grants.
//
// WHY staff never reach Twenty's new-workspace-creation branch: this
// tenant's Twenty instance has at most one workspace ever (Phase 24 D-01,
// one container per tenant) — the owner's first SSO login creates it; a
// staff principal arriving before that workspace exists is refused outright
// (prohibition: staff never gets workspace-creating/admin rights). A staff
// principal joining an existing workspace always goes through
// signInUpOnExistingWorkspace's default-role path, never with a roleId
// override.
@Injectable()
export class PlatformOidcAuthService {
  constructor(
    private readonly authService: AuthService,
    private readonly signInUpService: SignInUpService,
    private readonly loginTokenService: LoginTokenService,
    private readonly userService: UserService,
    private readonly guardRedirectService: GuardRedirectService,
    private readonly workspaceDomainsService: WorkspaceDomainsService,
    @InjectRepository(WorkspaceEntity)
    private readonly workspaceRepository: Repository<WorkspaceEntity>,
  ) {}

  async signInUpFromPlatformOidc(user: PlatformOidcUser): Promise<string> {
    // One container per tenant (Phase 24 D-01) — the instance's single,
    // earliest-created workspace IS the tenant's workspace. A Twenty
    // instance never legitimately has more than one.
    const [workspace] = await this.workspaceRepository.find({
      order: { createdAt: 'ASC' },
      take: 1,
      relations: ['approvedAccessDomains'],
    });

    try {
      if (!workspace && user.principalType !== 'owner') {
        throw new AuthException(
          'Your CRM workspace has not been set up yet — ask the account owner to open CRM first.',
          AuthExceptionCode.FORBIDDEN_EXCEPTION,
        );
      }

      const existingUser = await this.userService.findUserByEmailWithWorkspaces(
        user.email,
      );

      const { userData } = this.authService.formatUserDataPayload(
        {
          firstName: user.firstName,
          lastName: user.lastName,
          email: user.email,
          picture: null,
          locale: undefined,
          isEmailAlreadyVerified: true,
        },
        existingUser,
      );

      let signedInUser;
      let resolvedWorkspace: WorkspaceEntity;

      if (!workspace) {
        // Owner's first SSO login on an instance with no workspace yet —
        // AuthService.signInUp/SignInUpService.signInUp always route a
        // workspace-less newUser through signUpOnNewWorkspace(userData) with
        // NO displayName/subdomain option (its public signature has none),
        // which throws "Workspace name is required". Call
        // signUpOnNewWorkspace directly instead, with a real displayName
        // derived from the owner's own name/email, so the owner becomes the
        // workspace's creator exactly as the public signInUp flow would,
        // just with a name Twenty's own onboarding wizard would otherwise
        // have had to prompt for interactively.
        const partialUserWithPicture =
          await this.signInUpService.computePartialUserFromUserPayload(
            userData.type === 'newUser' ? userData.newUserPayload : {
              email: existingUser?.email ?? user.email,
            },
            { provider: AuthProviderEnum.SSO },
          );

        const newWorkspaceResult = await this.signInUpService.signUpOnNewWorkspace(
          existingUser
            ? { type: 'existingUser', existingUser }
            : { type: 'newUserWithPicture', newUserWithPicture: partialUserWithPicture },
          { displayName: this.deriveWorkspaceDisplayName(user) },
        );

        signedInUser = newWorkspaceResult.user;
        resolvedWorkspace = newWorkspaceResult.workspace;
      } else {
        const { user: userResult, workspace: workspaceResult } =
          await this.authService.signInUp({
            userData,
            workspace,
            invitation: undefined,
            authParams: { provider: AuthProviderEnum.SSO },
          });

        signedInUser = userResult;
        resolvedWorkspace = workspaceResult;
      }

      const loginToken = await this.loginTokenService.generateLoginToken(
        signedInUser.email,
        resolvedWorkspace.id,
        AuthProviderEnum.SSO,
      );

      return this.authService.computeRedirectURI({
        loginToken: loginToken.token,
        workspace: resolvedWorkspace,
      });
    } catch (error) {
      return this.guardRedirectService.getRedirectErrorUrlAndCaptureExceptions(
        {
          error,
          workspace:
            this.workspaceDomainsService.getSubdomainAndCustomDomainFromWorkspaceFallbackOnDefaultSubdomain(
              workspace,
            ),
          pathname: AppPath.Verify,
        },
      );
    }
  }

  private deriveWorkspaceDisplayName(user: PlatformOidcUser): string {
    const name = `${user.firstName} ${user.lastName}`.trim();

    return name.length > 0 ? `${name}'s Workspace` : `${user.email}'s Workspace`;
  }
}
