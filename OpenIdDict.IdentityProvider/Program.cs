using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using OpenIdDict.IdentityProvider.Data;
using OpenIdDict.IdentityProvider.Models;
using OpenIdDict.IdentityProvider.Services;
using Fido2NetLib;
using Fido2NetLib.Development;
using OpenIddict.Abstractions;
using static OpenIddict.Abstractions.OpenIddictConstants;
using Quartz;

var builder = WebApplication.CreateBuilder(args);

// Add Aspire Service Defaults
builder.AddServiceDefaults();

// Add services to the container.
var connectionString = builder.Configuration.GetConnectionString("DefaultConnection") ?? throw new InvalidOperationException("Connection string 'DefaultConnection' not found.");

// Configure Entity Framework with SQL Server for production, SQLite for development
builder.Services.AddDbContext<ApplicationDbContext>(options =>
{
    if (builder.Environment.IsDevelopment())
    {
        options.UseSqlite(connectionString);
    }
    else
    {
        options.UseSqlServer(connectionString);
    }
    
    // Register the entity sets needed by OpenIddict
    options.UseOpenIddict();
});

builder.Services.AddDatabaseDeveloperPageExceptionFilter();

// Configure ASP.NET Core Identity with custom ApplicationUser
builder.Services.AddIdentity<ApplicationUser, IdentityRole>(options =>
{
    options.SignIn.RequireConfirmedAccount = false;
    options.User.RequireUniqueEmail = true;
    options.Password.RequireDigit = true;
    options.Password.RequiredLength = 8;
    options.Password.RequireNonAlphanumeric = true;
    options.Password.RequireUppercase = true;
    options.Password.RequireLowercase = true;
})
.AddRoles<IdentityRole>()
.AddEntityFrameworkStores<ApplicationDbContext>()
.AddDefaultTokenProviders()
.AddDefaultUI()
.AddTokenProvider<Fido2UserTwoFactorTokenProvider>("FIDO2");

// Configure session for FIDO2
builder.Services.AddDistributedMemoryCache();
builder.Services.AddSession(options =>
{
    options.IdleTimeout = TimeSpan.FromMinutes(20);
    options.Cookie.HttpOnly = true;
    options.Cookie.SameSite = SameSiteMode.None;
    options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
});

// Configure FIDO2
builder.Services.AddSingleton<IFido2>(sp =>
{
    var configuration = new Fido2Configuration
    {
        ServerDomain = builder.Configuration["Fido2:ServerDomain"] ?? "localhost",
        ServerName = builder.Configuration["Fido2:ServerName"] ?? "OpenIddict Identity Provider",
        Origins = builder.Configuration.GetSection("Fido2:Origins").Get<HashSet<string>>() ?? new HashSet<string> { "https://localhost:7001" },
        TimestampDriftTolerance = 300000
    };

    if (builder.Environment.IsDevelopment())
    {
        return new Fido2(configuration);
    }
    
    return new Fido2(configuration);
});

// Configure Quartz for background jobs
builder.Services.AddQuartz(options =>
{
    options.UseSimpleTypeLoader();
    options.UseInMemoryStore();
});

// Register the Quartz.NET service as a hosted service

// Configure OpenIddict
builder.Services.AddOpenIddict()
    .AddCore(options =>
    {
        options.UseEntityFrameworkCore()
               .UseDbContext<ApplicationDbContext>();
               
        options.UseQuartz();
    })
    .AddServer(options =>
    {
        // Enable the authorization and token endpoints
        options.SetAuthorizationEndpointUris("connect/authorize")
               .SetTokenEndpointUris("connect/token")
               .SetIntrospectionEndpointUris("connect/introspect");

        // Mark the "email", "profile" and "roles" scopes as supported scopes
        options.RegisterScopes(Scopes.Email, Scopes.Profile, Scopes.Roles, Scopes.OpenId);

        // Enable the flows
        options.AllowAuthorizationCodeFlow()
               .AllowRefreshTokenFlow()
               .AllowClientCredentialsFlow();

        // Register the signing and encryption credentials (development only)
        if (builder.Environment.IsDevelopment())
        {
            options.AddDevelopmentEncryptionCertificate()
                   .AddDevelopmentSigningCertificate();
        }
        else
        {
            // TODO: Add production certificates
            options.AddEphemeralEncryptionKey()
                   .AddEphemeralSigningKey();
        }

        // Register the ASP.NET Core host and configure the ASP.NET Core-specific options
        options.UseAspNetCore()
               .EnableAuthorizationEndpointPassthrough()
               .EnableTokenEndpointPassthrough()
               .EnableStatusCodePagesIntegration();
    })
    .AddValidation(options =>
    {
        // Import the configuration from the local OpenIddict server instance
        options.UseLocalServer();

        // Register the ASP.NET Core host
        options.UseAspNetCore();
    });

builder.Services.AddRazorPages();
builder.Services.AddControllers();

// Register the database initializer
builder.Services.AddScoped<ApplicationDbInitializer>();

var app = builder.Build();

// Initialize the database
using (var scope = app.Services.CreateScope())
{
    var initializer = scope.ServiceProvider.GetRequiredService<ApplicationDbInitializer>();
    await initializer.InitializeAsync();
}

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseMigrationsEndPoint();
    app.UseDeveloperExceptionPage();
}
else
{
    app.UseExceptionHandler("/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();

// Add session middleware for FIDO2
app.UseSession();

app.UseRouting();

// Add authentication and authorization middleware
app.UseAuthentication();
app.UseAuthorization();

// Map endpoints
app.MapRazorPages();
app.MapControllers();
app.MapDefaultEndpoints(); // Aspire health checks

app.Run();
