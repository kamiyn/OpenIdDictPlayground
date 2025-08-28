using Microsoft.AspNetCore.Identity;

namespace OpenIdDict.IdentityProvider.Models;

public class ApplicationUser : IdentityUser
{
    public string? DisplayName { get; set; }
    public DateTime? LastLoginDate { get; set; }
    public new bool TwoFactorEnabled { get; set; }
    public bool Fido2Enabled { get; set; }
}