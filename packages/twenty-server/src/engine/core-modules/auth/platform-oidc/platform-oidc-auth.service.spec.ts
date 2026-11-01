import { AuthException } from 'src/engine/core-modules/auth/auth.exception';
import { PlatformOidcAuthService } from 'src/engine/core-modules/auth/platform-oidc/platform-oidc-auth.service';
import { type PlatformOidcUser } from 'src/engine/core-modules/auth/platform-oidc/platform-oidc.auth.strategy';
import { AuthProviderEnum } from 'src/engine/core-modules/workspace/types/workspace.type';

describe('PlatformOidcAuthService', () => {
  let authService: any;
  let signInUpService: any;
  let loginTokenService: any;
  let userService: any;
  let guardRedirectService: any;
  let workspaceDomainsService: any;
  let workspaceRepository: any;
  let service: PlatformOidcAuthService;

  const owner: PlatformOidcUser = {
    email: 'owner@tenant.example.com',
    firstName: 'Ann',
    lastName: 'Lee',
    principalType: 'owner',
    subject: 'owner-sub',
  };

  const staff: PlatformOidcUser = {
    email: 'staff@tenant.example.com',
    firstName: 'Sam',
    lastName: 'Staffer',
    principalType: 'staff',
    subject: 'staff-sub',
  };

  const existingWorkspace = { id: 'workspace-1', createdAt: new Date() };
  const createdWorkspace = { id: 'workspace-new', createdAt: new Date() };
  const createdUser = { id: 'user-1', email: owner.email };

  beforeEach(() => {
    authService = {
      formatUserDataPayload: jest.fn((newUserPayload, existingUser) => ({
        userData: existingUser
          ? { type: 'existingUser', existingUser }
          : { type: 'newUser', newUserPayload },
      })),
      signInUp: jest.fn(),
      computeRedirectURI: jest.fn(
        () => 'https://tenant.crm.example.com/verify?loginToken=abc',
      ),
    };

    signInUpService = {
      computePartialUserFromUserPayload: jest.fn(async (payload) => ({
        ...payload,
      })),
      signUpOnNewWorkspace: jest.fn(async () => ({
        user: createdUser,
        workspace: createdWorkspace,
      })),
    };

    loginTokenService = {
      generateLoginToken: jest.fn(async () => ({ token: 'login-token' })),
    };

    userService = {
      findUserByEmailWithWorkspaces: jest.fn(async () => null),
    };

    guardRedirectService = {
      getRedirectErrorUrlAndCaptureExceptions: jest.fn(
        () => 'https://tenant.crm.example.com/verify?errorMessage=denied',
      ),
    };

    workspaceDomainsService = {
      getSubdomainAndCustomDomainFromWorkspaceFallbackOnDefaultSubdomain: jest.fn(
        () => ({ subdomain: 'default', customDomain: null }),
      ),
    };

    workspaceRepository = {
      find: jest.fn(async () => []),
    };

    service = new PlatformOidcAuthService(
      authService,
      signInUpService,
      loginTokenService,
      userService,
      guardRedirectService,
      workspaceDomainsService,
      workspaceRepository,
    );
  });

  it('owner principal, no workspace: creates the new workspace and returns the login redirect', async () => {
    workspaceRepository.find.mockResolvedValue([]);

    const result = await service.signInUpFromPlatformOidc(owner);

    expect(signInUpService.signUpOnNewWorkspace).toHaveBeenCalledTimes(1);
    expect(authService.signInUp).not.toHaveBeenCalled();
    expect(loginTokenService.generateLoginToken).toHaveBeenCalledWith(
      createdUser.email,
      createdWorkspace.id,
      AuthProviderEnum.SSO,
    );
    expect(result).toBe('https://tenant.crm.example.com/verify?loginToken=abc');
  });

  it('staff principal, no workspace: throws FORBIDDEN and never calls signInUp', async () => {
    workspaceRepository.find.mockResolvedValue([]);

    const result = await service.signInUpFromPlatformOidc(staff);

    expect(authService.signInUp).not.toHaveBeenCalled();
    expect(signInUpService.signUpOnNewWorkspace).not.toHaveBeenCalled();
    expect(
      guardRedirectService.getRedirectErrorUrlAndCaptureExceptions,
    ).toHaveBeenCalledTimes(1);
    const callArgs =
      guardRedirectService.getRedirectErrorUrlAndCaptureExceptions.mock
        .calls[0][0];

    expect(callArgs.error).toBeInstanceOf(AuthException);
    expect(result).toBe(
      'https://tenant.crm.example.com/verify?errorMessage=denied',
    );
  });

  it('staff principal, existing workspace, unknown email: signInUp called with newUser userData and no roleId override', async () => {
    workspaceRepository.find.mockResolvedValue([existingWorkspace]);
    userService.findUserByEmailWithWorkspaces.mockResolvedValue(null);
    authService.signInUp.mockResolvedValue({
      user: { id: 'staff-user', email: staff.email },
      workspace: existingWorkspace,
    });

    await service.signInUpFromPlatformOidc(staff);

    expect(authService.signInUp).toHaveBeenCalledTimes(1);
    const callArgs = authService.signInUp.mock.calls[0][0];

    expect(callArgs.userData.type).toBe('newUser');
    expect(callArgs.workspace).toBe(existingWorkspace);
    expect(callArgs.authParams).toEqual({ provider: AuthProviderEnum.SSO });
    expect(callArgs).not.toHaveProperty('roleId');
  });

  it('owner or staff principal, existing workspace, known email: signInUp called with existingUser userData', async () => {
    const knownUser = { id: 'known-user', email: owner.email };

    workspaceRepository.find.mockResolvedValue([existingWorkspace]);
    userService.findUserByEmailWithWorkspaces.mockResolvedValue(knownUser);
    authService.signInUp.mockResolvedValue({
      user: knownUser,
      workspace: existingWorkspace,
    });

    await service.signInUpFromPlatformOidc(owner);

    const callArgs = authService.signInUp.mock.calls[0][0];

    expect(callArgs.userData).toEqual({
      type: 'existingUser',
      existingUser: knownUser,
    });
  });

  it('never calls checkAccessForSignIn (D-07: broker modules claim is the access decision)', async () => {
    workspaceRepository.find.mockResolvedValue([existingWorkspace]);
    authService.signInUp.mockResolvedValue({
      user: { id: 'u', email: owner.email },
      workspace: existingWorkspace,
    });
    authService.checkAccessForSignIn = jest.fn();

    await service.signInUpFromPlatformOidc(owner);

    expect(authService.checkAccessForSignIn).not.toHaveBeenCalled();
  });

  it('converts a thrown error into a redirect error URL via guardRedirectService, never throwing', async () => {
    workspaceRepository.find.mockResolvedValue([existingWorkspace]);
    authService.signInUp.mockRejectedValue(new Error('boom'));

    const result = await service.signInUpFromPlatformOidc(owner);

    expect(
      guardRedirectService.getRedirectErrorUrlAndCaptureExceptions,
    ).toHaveBeenCalledTimes(1);
    expect(result).toBe(
      'https://tenant.crm.example.com/verify?errorMessage=denied',
    );
  });
});
