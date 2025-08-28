# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is an OpenIddict-based OAuth 2.0/OpenID Connect solution built with .NET 8 and .NET Aspire. The architecture follows a distributed microservices pattern with three main components:

### Core Components

1. **Identity Provider** (`OpenIdDict.IdentityProvider`) - Authorization Server on port 7001
   - OpenIddict server implementation with ASP.NET Core Identity
   - FIDO2/WebAuthn passwordless authentication support
   - SQLite database for development, SQL Server for production
   - Manages users, clients, scopes, and token issuance

2. **Client Application** (`OpenIdDict.Client`) - OAuth Client on port 7002
   - Razor Pages application with OpenID Connect authentication
   - Demonstrates authorization code flow with PKCE
   - Shows claims and user information after authentication

3. **App Host** (`OpenIdDict.AppHost`) - .NET Aspire Orchestrator
   - Manages service discovery and inter-service communication
   - Configures SQL Server dependency for production scenarios

4. **Service Defaults** (`OpenIdDict.ServiceDefaults`) - Shared Infrastructure
   - Common Aspire services: telemetry, health checks, resilience patterns
   - OpenTelemetry configuration for distributed tracing

## Development Commands

### Build and Run
```bash
# Build entire solution
dotnet build

# Run Identity Provider only
cd OpenIdDict.IdentityProvider && dotnet run

# Run Client Application only  
cd OpenIdDict.Client && dotnet run

# Run with Aspire orchestration (recommended)
cd OpenIdDict.AppHost && dotnet run
```

### Database Operations
```bash
# Apply/update database migrations (from IdentityProvider directory)
dotnet ef database update

# Create new migration
dotnet ef migrations add <MigrationName>

# List migrations
dotnet ef migrations list
```

### Testing Authentication Flow
1. Start both applications (Identity Provider and Client)
2. Navigate to Client at https://localhost:7002
3. Click "Login" to initiate OAuth flow
4. Authenticate with seeded users:
   - Admin: `admin@openiddict.local` / `Admin@123456`
   - User: `user@openiddict.local` / `User@123456`

## Architecture Details

### Authentication Flow
The solution implements OAuth 2.0 Authorization Code Flow with PKCE:
1. Client redirects user to Identity Provider's `/connect/authorize` endpoint
2. User authenticates via ASP.NET Core Identity (with optional FIDO2)
3. Identity Provider issues authorization code to client's `/signin-oidc` callback
4. Client exchanges code for access/refresh tokens at `/connect/token` endpoint
5. Client uses tokens to access protected resources

### Database Schema
- **ASP.NET Core Identity tables**: Users, roles, claims management
- **OpenIddict tables**: Applications, authorizations, scopes, tokens
- **FIDO2 tables**: Stored credentials for passwordless authentication

### Configuration Management
- Client applications are registered via `appsettings.json` in IdentityProvider
- OpenIddict scopes: `openid`, `profile`, `email`, `roles`
- Development uses ephemeral signing/encryption keys
- FIDO2 origins configured for cross-origin authentication

### Key Integration Points
- `ApplicationDbInitializer.cs`: Seeds database with default users and OAuth clients
- `AuthorizationController.cs`: Handles OAuth authorization endpoint logic
- `Fido2Controller.cs`: WebAuthn credential registration and authentication
- Client authentication is configured in `Program.cs` with cookie + OIDC schemes

### Service Communication
The Aspire AppHost configures service-to-service communication:
- Identity Provider exposes external HTTPS endpoints for client access
- SQL Server database shared between services in production
- Health checks and telemetry enabled across all services

### Development Notes
- SQLite used for local development, SQL Server for production
- SSL certificate validation disabled in development for easier testing
- All services include Aspire service defaults for observability
- FIDO2 configured for localhost origins in development