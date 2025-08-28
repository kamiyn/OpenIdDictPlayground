using Microsoft.AspNetCore.Identity;
using OpenIdDict.IdentityProvider.Models;

namespace OpenIdDict.IdentityProvider.Services;

public class Fido2UserTwoFactorTokenProvider : IUserTwoFactorTokenProvider<ApplicationUser>
{
    public Task<bool> CanGenerateTwoFactorTokenAsync(
        UserManager<ApplicationUser> manager,
        ApplicationUser user)
    {
        return Task.FromResult(user.Fido2Enabled);
    }

    public Task<string> GenerateAsync(
        string purpose,
        UserManager<ApplicationUser> manager,
        ApplicationUser user)
    {
        // FIDO2 doesn't use traditional tokens
        return Task.FromResult(string.Empty);
    }

    public Task<bool> ValidateAsync(
        string purpose,
        string token,
        UserManager<ApplicationUser> manager,
        ApplicationUser user)
    {
        // FIDO2 validation happens through WebAuthn challenge/response
        // This is handled by the FIDO2 library, not through token validation
        return Task.FromResult(false);
    }
}