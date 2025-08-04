using PlatformApi.Models;
using PlatformApi.Models.DTOs;

namespace PlatformApi.Services;

public interface IOldUserService
{
    Task<IEnumerable<Role>> GetUserRoles(string userId, Guid? tenantId);
    Task<bool> AddUserToRole(string userId, Guid tenantId, Guid roleId);
    Task<bool> DoesUserHavePermission(string userId, string checkPermission, Guid? tenantId);
    Task<IEnumerable<Permission>?> GetUserPermissions(string userId, Guid? tenantId);
    Task<IEnumerable<Tenant?>> GetUserTenants(string userId);
    Task<bool> AddUserToTenant(string userId, Guid tenantId);
    Task<bool> AddUserToAdminRole(string userId, Guid roleId);
    
    // New methods for tenant user management
    Task<IEnumerable<TenantUserWithRolesDto>> GetTenantUsersWithNonGuestRoles(Guid tenantId);
    Task<IEnumerable<AuthUser>> GetTenantUsersByRoleName(Guid tenantId, string roleName);
    Task<bool> RemoveUserFromRole(string userId, Guid tenantId, Guid roleId);
    Task<AuthUser?> GetUserByEmail(string email);
    Task<IEnumerable<Role>> GetUserRolesExcludingGuest(string userId, Guid? tenantId);
    bool InvalidateUserPermissions(string userId, Guid? tenantId = null);
    Task PublishUserModifiedAsync(string userId, string email);
    
    // User invitation methods
    Task<InvitationResponse> InviteUserAsync(InviteUserRequest request, string invitedByUserId);
    Task<UserInvitation?> ValidateInvitationTokenAsync(string token);
    
    // User existence check
    Task<UserExistenceCheckDto> CheckUserExistenceAsync(string email, Guid tenantId);
    
    // User invitations
    Task<IEnumerable<UserInvitation>> GetPendingInvitationsAsync(Guid tenantId);
}