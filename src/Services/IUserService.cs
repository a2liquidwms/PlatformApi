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
    Task<bool> AddInternalRole(string email, Guid roleId);
    Task<bool> RemoveInternalRole(string email, Guid roleId);
    
    // User lookup helpers
    Task<AuthUser?> GetUserByEmail(string email);
    Task<IEnumerable<Role>> GetUserRoles(Guid userId, RoleScope scope, Guid? tenantId = null, Guid? siteId = null);
    Task<IEnumerable<Permission>?> GetUserPermissions(Guid userId, Guid? tenantId = null, Guid? siteId = null);
}