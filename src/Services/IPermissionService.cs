using PlatformApi.Models;

namespace PlatformApi.Services;

public interface IPermissionService
{
    Task<IEnumerable<Permission>> GetAllPermissions();
    Task<Permission?> GetPermissionByCode(string code);
    Task<Permission> AddPermission(Permission obj);
    Task<bool> UpdatePermission(string code, Permission obj);
    Task<bool> DeletePermission(string code);
    Task<IEnumerable<AuthRole>> GetAllRoles(bool includePermissions = false);
    Task<AuthRole?> GetRoleById(string id, bool includePermissions = false);
    Task<AuthRole?> GetRoleByName(string code, bool includePermissions = false);
    Task<AuthRole> AddRole(AuthRole obj);
    Task<bool> UpdateRole(string id, AuthRole obj);
    Task<bool> DeleteRole(string id);
    Task<AuthRole> AddPermissionsToRole(string roleId, string[] permissionCodes);
    Task<AuthRole> AddPermissionToRole(string roleId, string permissionCode);
    Task<AuthRole> RemovePermissionFromRole(string roleId, string permissionCode);
    Task<int> AddPermissionsMulti(Permission[] objs);
}