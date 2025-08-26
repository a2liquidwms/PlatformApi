using PlatformApi.Models;
using PlatformApi.Models.DTOs;

namespace PlatformApi.Services;

public interface IUserService
{
    // Get users by scope
    Task<IEnumerable<TenantUserWithRolesDto>> GetTenantUsers(Guid tenantId);
    Task<IEnumerable<SiteUserWithRolesDto>> GetSiteUsers(Guid siteId);
    Task<IEnumerable<InternalUserWithRolesDto>> GetInternalUsers();
    
    
    // Role management (scope-aware)
    Task<bool> AddUserToRole(AddUserToRoleDto dto);
    Task<bool> AddUserToRole(AddUserToRoleDto dto, RoleScope expectedScope);
    
    // Secure role removal (scope-specific)
    Task RemoveUserFromRole(RemoveUserFromRoleDto dto, RoleScope expectedScope);
    
    // User lookup helpers
    Task<AuthUser?> GetUserByEmail(string email);
    Task<UserLookupDto?> GetUserByUserName(string userName);
    Task<IEnumerable<Role>> GetUserRoles(Guid userId, RoleScope scope, Guid? tenantId = null, Guid? siteId = null);
    Task<IEnumerable<Permission>?> GetUserPermissions(Guid userId, Guid? tenantId = null, Guid? siteId = null);
    
    // User membership lookups
    Task<IEnumerable<TenantDto>> GetUserTenants(Guid userId, bool forLogin = false);
    Task<IEnumerable<SiteDto>> GetUserSites(Guid userId, Guid tenantId, bool forLogin = false);
    
    // User membership counts
    Task<int> GetUserTenantCount(Guid userId);
    Task<int> GetUserSiteCount(Guid userId, Guid tenantId);
    
    // User membership validation
    Task<bool> HasTenantAccess(Guid userId, Guid tenantId, bool forLogin = false);
    Task<bool> HasSiteAccess(Guid userId, Guid siteId, Guid tenantId, bool forLogin = false);
    
    // User invitation methods
    Task<InvitationResponse> InviteUserAsync(InviteUserRequest request, string invitedByUserId);
    Task<UserInvitation?> ValidateInvitationTokenAsync(string token);
    Task<UserExistenceCheckDto> CheckUserExistenceAsync(string email, Guid tenantId);
    Task<IEnumerable<UserInvitation>> GetPendingInvitationsAsync(Guid tenantId);
    
    // User removal methods
    Task RemoveUserFromTenant(Guid userId, Guid tenantId);
    Task RemoveUserFromSite(Guid userId, Guid siteId);
    
    // Cache invalidation methods
    void InvalidateUserTenantCache(Guid userId);
    void InvalidateAllUserTenantCaches();
}