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

### Service Responsibilities (Refined Architecture)

- **PermissionService**: Role/Permission entity management (CRUD operations)
  - Create/Update/Delete roles and permissions
  - Link permissions to roles
  - System-wide role definitions

- **UserService**: User relationship and context queries
  - User-tenant/site memberships
  - User role assignments (contextual)
  - User permission resolution (contextual)
  - User access validation

- **AuthService**: Authentication flows only
  - Login/logout
  - Token generation (using UserService for claims)
  - Email workflows

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

## Authentication Architecture

### API-Only Authentication
This application provides authentication through API endpoints only. Frontend React applications handle the UI presentation:

**Authentication Flow:**
- React apps make requests to authentication API endpoints
- JWT tokens are returned for successful authentication
- Cross-subdomain cookie support for multi-tenant React apps
- Branding context provided through `IBrandingService` for tenant-specific theming

**API Endpoints:**
- Authentication endpoints in `AuthController` 
- User management endpoints in `UserController`
- Tenant management endpoints in `TenantController`

**Cross-Subdomain Support:**
- Cookies set with `Domain=.mysite.com` for cross-subdomain access
- Branding service provides tenant context based on subdomain resolution
- JWT tokens include tenant-specific claims

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

## Logging Guidelines

This codebase follows structured logging practices with specific patterns for different scenarios and log levels.

### Log Levels and Usage

**Debug**: Important application details that may be needed for troubleshooting
- JWT claims generation and validation details
- Complex business logic flows and decision points
- Data transformation and mapping operations
- Debugging information for specific production issues

**Information**: Default logging level for normal application operations
- Successful authentication activities (login, registration, password reset)
- CRUD operations completion
- API endpoint calls and responses
- User actions and state changes
- System startup and configuration events

**Warning**: Client errors (4xx) and failed operations that don't break the system
- Failed authentication attempts (bad passwords, invalid tokens, expired sessions)
- Validation failures and business rule violations
- Missing or invalid request data
- Authorization failures
- Deprecated feature usage

**Error**: System errors (5xx) and exceptions that affect functionality
- Unhandled exceptions in controllers and services
- Database connection failures
- External service integration failures
- Infrastructure and configuration errors

**Critical**: System failures requiring immediate attention
- Application startup failures
- Security breaches or suspicious activities
- Complete system outages

### Structured Logging Patterns

Use consistent structured logging with meaningful properties:

```csharp
// Good: Structured logging with context
_logger.LogInformation("User {Email} logged in successfully with tenant {TenantId} and site {SiteId}", 
    request.Email, request.TenantId, request.SiteId);

// Good: Warning for failed attempts
_logger.LogWarning("Login attempt failed - user not found for email: {Email}", email);

// Good: Debug with detailed context
_logger.LogDebug("Generated {ClaimCount} total claims for user {UserId} with context tenant {TenantId}, site {SiteId}", 
    allClaims.Count, user.Id, tenantId, siteId);
```

**Key Properties to Include**:
- `UserId` - For user-specific operations
- `Email` - For authentication operations (before UserId is available)
- `TenantId` - For multi-tenant context
- `SiteId` - For site-specific operations
- `RequestId` - For request correlation
- Entity IDs for CRUD operations

### Authentication Logging Requirements

Based on `AuthController` and `AuthService` implementations:

**Information Level** (successful operations):
- User login, registration, email confirmation
- Password reset initiation and completion
- Token refresh operations
- Tenant and site switching
- Session management activities

**Warning Level** (failed attempts):
- Invalid login credentials
- Expired or invalid tokens
- Email confirmation failures
- Password reset failures
- Authorization violations

**Debug Level** (troubleshooting details):
- JWT token claims generation
- Permission resolution details
- Complex authentication flow steps

### Controller Exception Handling with Logging

Controllers should catch service exceptions and log appropriately:

```csharp
try 
{
    await _service.SomeMethod(dto);
    _logger.LogInformation("Operation completed successfully for {Context}", contextInfo);
    return Ok(new { Message = "Success message" });
}
catch (NotFoundException ex)
{
    _logger.LogWarning("Resource not found: {Message}", ex.Message);
    return NotFound(ex.Message);
}
catch (InvalidDataException ex)
{
    _logger.LogWarning("Invalid request data: {Message}", ex.Message);
    return BadRequest(ex.Message);
}
catch (Exception ex)
{
    _logger.LogError(ex, "Unexpected error in {Operation}", "OperationName");
    return StatusCode(500, "Internal server error");
}
```

### Framework Noise Management

The application filters Microsoft framework logs to reduce noise while preserving essential information:

**Framework Filtering** (configured in `Program.cs`):
```csharp
// Filter out Microsoft framework debug noise
builder.Logging.AddFilter("Microsoft", LogLevel.Warning);

// Override for essential Microsoft logs at Information level
builder.Logging.AddFilter("Microsoft.AspNetCore.Authentication", LogLevel.Information);
builder.Logging.AddFilter("Microsoft.AspNetCore.Authorization", LogLevel.Information);  
builder.Logging.AddFilter("Microsoft.AspNetCore.Routing.EndpointMiddleware", LogLevel.Information);
builder.Logging.AddFilter("Microsoft.Hosting.Lifetime", LogLevel.Information);
```

**EF Core Noise Control**:
- Use `LOGGING_EF_VERBOSE=false` environment variable to suppress EF query noise
- Database command logging filtered to Warning level unless explicitly enabled

### Security Logging Considerations

**DO Log**:
- Authentication successes and failures with context
- Authorization failures with user and resource context
- Security-related configuration changes
- Token generation and validation events

**DON'T Log**:
- Passwords or other secrets
- Complete JWT tokens (only claims for debugging)
- Personal data unless necessary for security auditing
- Sensitive business data in plain text

### Performance Considerations

- Use structured logging parameters instead of string interpolation
- Avoid expensive operations in log statements
- Consider log level guards for complex Debug statements:
  ```csharp
  if (_logger.IsEnabled(LogLevel.Debug))
  {
      _logger.LogDebug("Complex debug info: {Data}", ExpensiveOperation());
  }
  ```