var builder = DistributedApplication.CreateBuilder(args);

// Add SQL Server with a persistent data volume and database
var sqlServer = builder.AddSqlServer("sql")
    .WithDataVolume()
    .AddDatabase("OpenIddictDb");

// Add Identity Provider with reference to SQL Server
var identityProvider = builder.AddProject<Projects.OpenIdDict_IdentityProvider>("identityprovider")
    .WithReference(sqlServer)
    .WithExternalHttpEndpoints();

// Add Client Application with reference to Identity Provider
var client = builder.AddProject<Projects.OpenIdDict_Client>("client")
    .WithReference(identityProvider);

builder.Build().Run();
