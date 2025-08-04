# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a multi-tenant ASP.NET Core 8 Web API platform that provides authentication, authorization, tenant management, and user management services. The project uses Entity Framework Core with MySQL, JWT authentication, Google OAuth integration, and AWS services (SES for email, SNS for notifications).

## Development Commands

### Build and Run
```bash
# Build the solution
dotnet build PlatformApi.sln

# Run the main API (from src directory)
cd src && dotnet run

# Run with specific profile
cd src && dotnet run --launch-profile https
```

### Testing
```bash
# Run all tests
dotnet test

# Run tests with coverage
dotnet test --collect:"XPlat Code Coverage"

# Run specific test project
dotnet test PlatformApiTests/
```

### Database Operations
```bash
# Add new migration
cd src && dotnet ef migrations add <MigrationName>

# Update database
cd src && dotnet ef database update

# Apply manual database updates
mysql -u netuser -p netstarterauth < src/database-update.sql
```

### Docker
```bash
# Build Docker image
docker build -t platformapi .

# Run containerized application
docker run -p 8080:8080 platformapi
```

## Architecture Overview

### Core Components

**Multi-tenant Architecture**: The system supports multiple tenants with tenant-specific user roles and permissions. Tenant context is resolved through middleware and helper classes.

**Authentication Flow**: 
- JWT-based authentication with refresh tokens
- Google OAuth integration
- Email confirmation and password reset workflows
- Invitation-based user registration

**Permission System**: 
- Role-based permissions with tenant-specific assignments
- Custom middleware (`PermissionsAuthServerMiddleware`) for authorization
- Permission attributes for controller actions

**Data Layer**:
- `PlatformDbContext` extends `IdentityDbContext` for user management
- Snake case naming convention for database tables
- Entity relationships for multi-tenant user-role assignments

### Key Services

- `IAuthService` - Authentication operations, email confirmation, password management
- `ITenantService` - Tenant creation and management
- `IUserService` - User management and tenant associations
- `IPermissionService` - Role and permission management
- `IEmailService` - AWS SES integration for email notifications
- `ISnsService` - AWS SNS integration for notifications

### External Dependencies

- **MySQL Database**: Primary data store with Entity Framework Core
- **AWS SES**: Email service for confirmations and notifications
- **AWS SNS**: Push notification service
- **Google OAuth**: Third-party authentication provider

## Configuration

Environment variables are loaded from `.env` file (see `.env.example`). Key configuration includes:
- Database connection string (`DBCONNECTION_AUTH`)
- JWT settings (`JWT_SECRET`, `JWT_ISSUER`, `JWT_AUDIENCE`)
- AWS credentials and regions
- Google OAuth client credentials
- Email and UI domain configurations

## Development Notes

The project includes a `TempStarter` directory containing common utilities and middleware from `NetStarterCommon.Core` that provide:
- Tenant resolution and middleware
- Permission handling and authorization policies
- Common authentication utilities
- Base models and constants

When working with this codebase, be aware of the multi-tenant nature - most operations should consider tenant context, and user permissions are scoped to specific tenants.

## Claude Code Guidelines

### Migration and Database Changes
- If a migration is needed as part of change, I will run manually.  At end of prompt, just add "Migration is Needed", if there are db changes.  