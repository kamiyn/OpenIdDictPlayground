using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using OpenIdDict.IdentityProvider.Models;

namespace OpenIdDict.IdentityProvider.Data;

public class ApplicationDbContext : IdentityDbContext<ApplicationUser>
{
    public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
        : base(options)
    {
    }

    public DbSet<FidoStoredCredential> FidoStoredCredentials { get; set; }

    protected override void OnModelCreating(ModelBuilder builder)
    {
        base.OnModelCreating(builder);

        // Configure OpenIddict entities
        builder.UseOpenIddict();
        
        // Configure FIDO2 credential entity
        builder.Entity<FidoStoredCredential>(entity =>
        {
            entity.HasIndex(c => c.UserHandle);
            entity.HasIndex(c => c.UserId);
            entity.HasIndex(c => new { c.UserId, c.CredentialId }).IsUnique();
        });

        // Configure ApplicationUser
        builder.Entity<ApplicationUser>(entity =>
        {
            entity.Property(u => u.DisplayName).HasMaxLength(100);
        });
    }
}
