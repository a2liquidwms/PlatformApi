using PlatformApi.Common.Auth;
using PlatformApi.Models;

namespace PlatformApi.Services;

public interface IPermissionService
{
    Task<IEnumerable<Permission>> GetAllPermissions(int? scope = null);
    Task<Permission?> GetPermissionByCode(string code);
    Task<Permission> AddPermission(Permission obj);
    Task<bool> UpdatePermission(string code, Permission obj);
    Task<bool> DeletePermission(string code);
    Task<IEnumerable<Role>> GetAllRoles(bool includePermissions = false);
    Task<Role?> GetRoleById(string id, bool includePermissions = false);
    Task<Role?> GetRoleByName(string code, bool includePermissions = false);
    Task<Role> AddRole(Role obj);
    Task<bool> UpdateRole(string id, Role obj);
    Task<bool> DeleteRole(string id);
    Task<Role> AddPermissionsToRole(string roleId, string[] permissionCodes);
    Task<Role> AddPermissionToRole(string roleId, string permissionCode);
    Task<Role> RemovePermissionFromRole(string roleId, string permissionCode);
    Task<int> AddPermissionsMulti(Permission[] objs);
    Task<List<CommonRolesPermission>> GetAllRolesWithPermissionsCached();
    void InvalidateRolePermissionCache();
}