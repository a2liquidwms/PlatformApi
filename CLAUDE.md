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

### Exception Handling Pattern
This codebase follows a consistent exception handling pattern where services throw specific exceptions that are caught and handled in controllers:

**Service Layer**: Throw specific exceptions instead of returning false/null:
- `NotFoundException` - When entities (users, roles, etc.) are not found
- `InvalidDataException` - For validation errors, scope mismatches, invalid data
- Let other exceptions bubble up naturally

**Controller Layer**: Catch and convert exceptions to appropriate HTTP responses:
```csharp
try 
{
    await _service.SomeMethod(dto);
    return Ok(new { Message = "Success message" });
}
catch (NotFoundException ex)
{
    return NotFound(ex.Message);
}
catch (InvalidDataException ex)
{
    return BadRequest(ex.Message);
}
catch (Exception ex)
{
    _logger.LogError(ex, "Error description");
    return StatusCode(500, "Internal server error");
}
```

**Available Exceptions** (from `NetStarterCommon.Core.Common.Constants`):
- `NotFoundException` - Returns 404 Not Found
- `InvalidDataException` - Returns 400 Bad Request (standard .NET exception)
- Generic `Exception` - Returns 500 Internal Server Error

**Example**: See `TenantController.Update()` method and `UserController` AddUserToRole endpoints for reference implementations.

### Unit of Work Pattern
This codebase uses the Unit of Work pattern for database operations instead of calling `SaveChangesAsync()` directly on the DbContext:

**Service Layer Requirements**:
- Inject `IUnitOfWork<PlatformDbContext> _uow` in constructor
- Use `await _uow.CompleteAsync();` instead of `await _context.SaveChangesAsync();`
- No additional using statement needed - `IUnitOfWork` is available in the `PlatformApi.Services` namespace

**Constructor Pattern**:
```csharp
private readonly IUnitOfWork<PlatformDbContext> _uow;

public MyService(
    PlatformDbContext context,
    IUnitOfWork<PlatformDbContext> uow,
    // other dependencies
)
{
    _context = context;
    _uow = uow;
    // other assignments
}
```

**Usage Pattern**:
```csharp
// Add/Update/Remove entities using _context
_context.MyEntities.Add(entity);
// or
_context.MyEntities.Update(entity);
// or  
_context.MyEntities.Remove(entity);

// Commit all changes using Unit of Work
await _uow.CompleteAsync();
```

**Example**: See `TenantService` methods (Add, Update, Delete, UpdateTenantConfig) for reference implementations.

### Migration and Database Changes
- If a migration is needed as part of change, I will run manually.  At end of prompt, just add "Migration is Needed", if there are db changes.  