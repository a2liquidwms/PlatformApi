# CLAUDE.md

This file provides guidance to Claude Code when working with this repository.

## Project Overview

.NET 8 multi-tenant SaaS platform starter app for microservices architecture. Responsible for Authentication, Authorization (roles/permissions), Tenant management, and User management. Each tenant can have multiple Sites with site-specific configuration.

**User Management Hierarchy**: Internal → Tenant → Site → Default levels. Higher RoleScopes have access to lower RoleScopes, but not vice versa.

## Architecture

**Patterns**: Controller → Service with clear separation. Use interfaces for external 3rd party services (AWS currently) to enable cloud provider flexibility.

**Data**: Postgres with Entity Framework Core, code-first migrations. AutoMapper for DTOs.

**Configuration**: Environment variables via `.env` file (see `.env.example`). No appsettings.json used.

**Auth**: JWT-based with refresh tokens, role-based permissions with tenant-specific assignments.

## Key Services

- `IAuthService` - Authentication flows only
- `ITenantService` - Tenant creation and management  
- `IUserService` - User relationships and context queries
- `IPermissionService` - Role/permission management
- `IEmailService` - AWS SES integration
- `ISnsService` - AWS SNS integration

## Development Commands

```bash
# Build and run
dotnet build
dotnet run

# Testing  
dotnet test
```

## Development Guidelines

**Exception Handling**: Services throw specific exceptions (`NotFoundException`, `InvalidDataException`). Controllers catch and return appropriate HTTP responses.

**Database**: Use Unit of Work pattern - inject `IUnitOfWork<PlatformDbContext>` and call `await _uow.CompleteAsync()` instead of `SaveChangesAsync()`.

**Logging**: Serilog with structured logging. Info level for normal operations, Debug for detailed troubleshooting. Controllers should not replicate service logging unless doing substantial work after service response.

**Migrations**: Manual only. Add "Migration is Needed" at end of response if database changes are made.

**IMPORTANT**: Ensure each function adheres to the Single Responsibility Principle to keep functions manageable and easy to test.