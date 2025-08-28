using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using OpenIddict.Abstractions;
using OpenIdDict.IdentityProvider.Models;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace OpenIdDict.IdentityProvider.Data;

public class ApplicationDbInitializer
{
    private readonly IServiceProvider _serviceProvider;
    private readonly IConfiguration _configuration;
    private readonly ILogger<ApplicationDbInitializer> _logger;

    public ApplicationDbInitializer(
        IServiceProvider serviceProvider,
        IConfiguration configuration,
        ILogger<ApplicationDbInitializer> logger)
    {
        _serviceProvider = serviceProvider;
        _configuration = configuration;
        _logger = logger;
    }

    public async Task InitializeAsync()
    {
        using var scope = _serviceProvider.CreateScope();
        
        var context = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
        
        // Ensure database is created and migrations are applied
        await context.Database.EnsureCreatedAsync();
        
        if (context.Database.GetPendingMigrations().Any())
        {
            await context.Database.MigrateAsync();
            _logger.LogInformation("Database migrations applied successfully.");
        }

        // Seed default users
        await SeedUsersAsync(scope.ServiceProvider);
        
        // Seed OpenIddict applications
        await SeedOpenIddictApplicationsAsync(scope.ServiceProvider);
    }

    private async Task SeedUsersAsync(IServiceProvider serviceProvider)
    {
        var userManager = serviceProvider.GetRequiredService<UserManager<ApplicationUser>>();
        var roleManager = serviceProvider.GetRequiredService<RoleManager<IdentityRole>>();

        // Create roles
        string[] roles = { "Administrator", "User" };
        foreach (var role in roles)
        {
            if (!await roleManager.RoleExistsAsync(role))
            {
                await roleManager.CreateAsync(new IdentityRole(role));
                _logger.LogInformation($"Role '{role}' created.");
            }
        }

        // Create admin user
        var adminEmail = "admin@openiddict.local";
        var adminUser = await userManager.FindByEmailAsync(adminEmail);
        
        if (adminUser == null)
        {
            adminUser = new ApplicationUser
            {
                UserName = adminEmail,
                Email = adminEmail,
                EmailConfirmed = true,
                DisplayName = "Administrator",
                TwoFactorEnabled = false,
                Fido2Enabled = false
            };

            var result = await userManager.CreateAsync(adminUser, "Admin@123456");
            if (result.Succeeded)
            {
                await userManager.AddToRoleAsync(adminUser, "Administrator");
                _logger.LogInformation($"Admin user '{adminEmail}' created with default password.");
            }
            else
            {
                _logger.LogError($"Failed to create admin user: {string.Join(", ", result.Errors.Select(e => e.Description))}");
            }
        }

        // Create test user
        var testEmail = "user@openiddict.local";
        var testUser = await userManager.FindByEmailAsync(testEmail);
        
        if (testUser == null)
        {
            testUser = new ApplicationUser
            {
                UserName = testEmail,
                Email = testEmail,
                EmailConfirmed = true,
                DisplayName = "Test User",
                TwoFactorEnabled = false,
                Fido2Enabled = false
            };

            var result = await userManager.CreateAsync(testUser, "User@123456");
            if (result.Succeeded)
            {
                await userManager.AddToRoleAsync(testUser, "User");
                _logger.LogInformation($"Test user '{testEmail}' created with default password.");
            }
            else
            {
                _logger.LogError($"Failed to create test user: {string.Join(", ", result.Errors.Select(e => e.Description))}");
            }
        }
    }

    private async Task SeedOpenIddictApplicationsAsync(IServiceProvider serviceProvider)
    {
        var manager = serviceProvider.GetRequiredService<IOpenIddictApplicationManager>();

        var applications = _configuration.GetSection("OpenIddict:Applications").Get<List<OpenIddictApplicationConfig>>() ?? new List<OpenIddictApplicationConfig>();

        foreach (var appConfig in applications)
        {
            if (await manager.FindByClientIdAsync(appConfig.ClientId) is null)
            {
                var descriptor = new OpenIddictApplicationDescriptor
                {
                    ClientId = appConfig.ClientId,
                    ClientSecret = appConfig.ClientSecret,
                    DisplayName = appConfig.DisplayName,
                    ConsentType = ConsentTypes.Implicit
                };

                // Add redirect URIs
                foreach (var uri in appConfig.RedirectUris ?? Enumerable.Empty<string>())
                {
                    descriptor.RedirectUris.Add(new Uri(uri));
                }

                // Add post-logout redirect URIs
                foreach (var uri in appConfig.PostLogoutRedirectUris ?? Enumerable.Empty<string>())
                {
                    descriptor.PostLogoutRedirectUris.Add(new Uri(uri));
                }

                // Add permissions
                foreach (var permission in appConfig.Permissions ?? Enumerable.Empty<string>())
                {
                    descriptor.Permissions.Add(permission);
                }

                await manager.CreateAsync(descriptor);
                _logger.LogInformation($"Application '{appConfig.ClientId}' created.");
            }
        }
    }

    private class OpenIddictApplicationConfig
    {
        public string ClientId { get; set; } = string.Empty;
        public string ClientSecret { get; set; } = string.Empty;
        public string DisplayName { get; set; } = string.Empty;
        public List<string>? RedirectUris { get; set; }
        public List<string>? PostLogoutRedirectUris { get; set; }
        public List<string>? Permissions { get; set; }
    }
}