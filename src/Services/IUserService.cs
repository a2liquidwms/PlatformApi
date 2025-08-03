using PlatformApi.Models;
using PlatformApi.Models.DTOs;

namespace PlatformApi.Services;

public interface IUserService
{
    // Get users by scope
    Task<IEnumerable<TenantUserWithRolesDto>> GetTenantUsers(Guid tenantId);
    Task<IEnumerable<SiteUserWithRolesDto>> GetSiteUsers(Guid siteId);
    
    // Add users to scope
    Task<bool> AddUserToTenant(AddUserToTenantDto dto);
    Task<bool> AddUserToSite(AddUserToSiteDto dto);
    
    // Role management (scope-aware)
    Task<bool> AddUserToRole(AddUserToRoleDto dto);
    Task<bool> RemoveUserFromRole(RemoveUserFromRoleDto dto);
    
    // Internal role management (system-wide)
    Task<bool> AddInternalRole(string email, string roleId);
    Task<bool> RemoveInternalRole(string email, string roleId);
    
    // User lookup helpers
    Task<AuthUser?> GetUserByEmail(string email);
    Task<IEnumerable<AuthRole>> GetUserRoles(string userId, RoleScope scope, Guid? tenantId = null, Guid? siteId = null);
    Task<IEnumerable<Permission>?> GetUserPermissions(string userId, Guid? tenantId = null, Guid? siteId = null);
}