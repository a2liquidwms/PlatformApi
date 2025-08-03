using PlatformApi.Data;
using PlatformApi.Models;
using PlatformApi.Models.DTOs;
using Microsoft.EntityFrameworkCore;

namespace PlatformApi.Services;

/// <summary>
/// Temporary legacy service to support AuthService while transitioning to new role system
/// </summary>
public class LegacyUserService : IOldUserService
{
    private readonly PlatformDbContext _context;

    public LegacyUserService(PlatformDbContext context)
    {
        _context = context;
    }

    public async Task<IEnumerable<AuthRole>> GetUserRoles(string userId, Guid? tenantId)
    {
        // Return empty list for now - will be handled by new permission system
        return new List<AuthRole>();
    }

    public async Task<bool> AddUserToRole(string userId, Guid tenantId, string roleId)
    {
        // TODO: Implement when role management is moved to dedicated service
        return true;
    }

    public async Task<IEnumerable<Tenant?>> GetUserTenants(string userId)
    {
        return await _context.UserTenants
            .Where(ut => ut.UserId == userId)
            .Include(ut => ut.Tenant)
            .Select(ut => ut.Tenant)
            .ToListAsync();
    }

    public async Task<bool> AddUserToTenant(string userId, Guid tenantId)
    {
        var existingUserTenant = await _context.UserTenants
            .FirstOrDefaultAsync(ut => ut.UserId == userId && ut.TenantId == tenantId);

        if (existingUserTenant != null) return true;

        var userTenant = new UserTenant
        {
            UserId = userId,
            TenantId = tenantId
        };

        await _context.UserTenants.AddAsync(userTenant);
        await _context.SaveChangesAsync();
        return true;
    }

    public async Task<UserInvitation?> ValidateInvitationTokenAsync(string token)
    {
        return await _context.UserInvitations
            .FirstOrDefaultAsync(ui => ui.InvitationToken == token && 
                                      !ui.IsUsed && 
                                      ui.ExpiresAt > DateTime.UtcNow);
    }

    // Not implemented methods - will be handled by dedicated services
    public Task<bool> DoesUserHavePermission(string userId, string checkPermission, Guid? tenantId)
        => throw new NotImplementedException("Use new permission system");

    public Task<IEnumerable<Permission>?> GetUserPermissions(string userId, Guid? tenantId)
        => throw new NotImplementedException("Use new permission system");

    public Task<bool> AddUserToAdminRole(string userId, string roleId)
        => throw new NotImplementedException("Use new role system");

    public Task<IEnumerable<TenantUserWithRolesDto>> GetTenantUsersWithNonGuestRoles(Guid tenantId)
        => throw new NotImplementedException("Use UserService");

    public Task<IEnumerable<AuthUser>> GetTenantUsersByRoleName(Guid tenantId, string roleName)
        => throw new NotImplementedException("Use new role system");

    public Task<bool> RemoveUserFromRole(string userId, Guid tenantId, string roleId)
        => throw new NotImplementedException("Use new role system");

    public Task<AuthUser?> GetUserByEmail(string email)
        => throw new NotImplementedException("Use UserService");

    public Task<IEnumerable<AuthRole>> GetUserRolesExcludingGuest(string userId, Guid? tenantId)
        => throw new NotImplementedException("Use new role system");

    public bool InvalidateUserPermissions(string userId, Guid? tenantId = null)
        => true;

    public Task PublishUserModifiedAsync(string userId, string email)
        => Task.CompletedTask;

    public Task<InvitationResponse> InviteUserAsync(InviteUserRequest request, string invitedByUserId)
        => throw new NotImplementedException("Use new invitation system");

    public Task<UserExistenceCheckDto> CheckUserExistenceAsync(string email, Guid tenantId)
        => throw new NotImplementedException("Use new user system");

    public Task<IEnumerable<UserInvitation>> GetPendingInvitationsAsync(Guid tenantId)
        => throw new NotImplementedException("Use new invitation system");
}