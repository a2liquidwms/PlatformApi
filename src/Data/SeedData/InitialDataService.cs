using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using PlatformApi.Models;
using PlatformStarterCommon.Core.Common.Services;

namespace PlatformApi.Data.SeedData;

public interface IInitialDataService
{
    Task EnsureInitialAdminUserAsync();
}

public class InitialDataService : IInitialDataService
{
    private readonly UserManager<AuthUser> _userManager;
    private readonly PlatformDbContext _context;
    private readonly IUnitOfWork<PlatformDbContext> _uow;
    private readonly ILogger<InitialDataService> _logger;
    private const string INITIAL_ADMIN_EMAIL = "aaron@liquidwms.com";
    private readonly Guid INITIAL_ADMIN_USER_ID = Guid.Parse("123e4567-e89b-12d3-a456-426614174000");

    public InitialDataService(UserManager<AuthUser> userManager, PlatformDbContext context, IUnitOfWork<PlatformDbContext> uow, ILogger<InitialDataService> logger)
    {
        _userManager = userManager;
        _context = context;
        _uow = uow;
        _logger = logger;
    }

    public async Task EnsureInitialAdminUserAsync()
    {
        // Check if database has been migrated by checking if there are no pending migrations
        var pendingMigrations = await _context.Database.GetPendingMigrationsAsync();
        var hasMigrated = !pendingMigrations.Any();
        
        if (!hasMigrated)
        {
            _logger.LogInformation("Database not fully migrated yet. Skipping initial data seeding.");
            return;
        }
        
        
        var existingUser = await _userManager.FindByEmailAsync(INITIAL_ADMIN_EMAIL);
        if (existingUser != null) return;

        var adminUser = new AuthUser
        {
            Id = INITIAL_ADMIN_USER_ID,
            UserName = INITIAL_ADMIN_EMAIL,
            Email = INITIAL_ADMIN_EMAIL,
            EmailConfirmed = true
        };

        _logger.LogInformation($"Creating Seed Data for new user {INITIAL_ADMIN_EMAIL}.");
        var result = await _userManager.CreateAsync(adminUser);
        if (!result.Succeeded)
        {
            throw new InvalidOperationException($"Failed to create initial admin user: {string.Join(", ", result.Errors.Select(e => e.Description))}");
        }

        // Assign SuperAdmin role
        var userRole = new UserRoles
        {
            Id = Guid.Parse("987fcdeb-51a2-43d7-8f9e-012345678901"),
            UserId = INITIAL_ADMIN_USER_ID,
            RoleId = Guid.Parse(AuthApiConstants.SUPERADMIN_ROLE),
            Scope = RoleScope.Internal,
            TenantId = null,
            SiteId = null,
            CreateDate = DateTime.UtcNow
        };

        await _context.UserRoles.AddAsync(userRole);
        await _uow.CompleteAsync();
    }
}