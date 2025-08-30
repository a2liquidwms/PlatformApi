using Microsoft.EntityFrameworkCore;
using PlatformStarterCommon.Core.Common.Auth;
using PlatformStarterCommon.Core.Common.Constants;
using PlatformStarterCommon.Core.Common.Services;
using PlatformApi.Data;
using PlatformApi.Models;

namespace PlatformApi.Services;

public class PermissionService : IPermissionService
{
    private readonly ILogger<PermissionService> _logger;
    private readonly PlatformDbContext _context;
    private readonly IUnitOfWork<PlatformDbContext> _uow;
    private readonly ITenantService _tenantService;
    private readonly ICacheService _cache;

    public PermissionService(ILogger<PermissionService> logger, PlatformDbContext context, IUnitOfWork<PlatformDbContext> uow,
        ITenantService tenantService, ICacheService cache)
    {
        _logger = logger;
        _context = context;
        _uow = uow;
        _tenantService = tenantService;
        _cache = cache;
    }

    public async Task<IEnumerable<Permission>> GetAllPermissions(int? scope = null)
    {
        var query = _context.Permissions.AsNoTracking();
        
        if (scope.HasValue)
        {
            var roleScope = (RoleScope)scope.Value;
            query = query.Where(p => p.RoleScope == null || p.RoleScope == roleScope);
        }
        
        return await query.ToListAsync();
    }
    
    public async Task<Permission?> GetPermissionByCode(string code)
    {
        return await _context.Permissions.AsNoTracking().FirstOrDefaultAsync(r => r.Code == code);
    }

    public async Task<Permission> AddPermission(Permission obj)
    {
        _context.Permissions.Add(obj);
        await _uow.CompleteAsync();
        
        _logger.LogInformation("Permission {PermissionCode} created successfully", obj.Code);
        return obj;
    }
    
    public async Task<int> AddPermissionsMulti(Permission[] objs)
    {
        try
        {
            foreach (var perm in objs)
            {
                _context.Permissions.Add(perm);
            }
            await _uow.CompleteAsync();
            
            _logger.LogInformation("Multiple permissions created successfully");
            return objs.Length;
        }
        catch (Exception ex)
        {
            var message = ex.InnerException?.Message ?? "Error saving Permissions";
            _logger.LogError(ex, "Failed to add multiple permissions: {Message}", message);
            throw new ArgumentException(message);
        }
    }

    public async Task<bool> UpdatePermission(string code, Permission obj)
    {
        if (code != obj.Code)
        {
            _logger.LogWarning("Invalid code mismatch for permission update: provided {ProvidedCode}, object {ObjectCode}", code, obj.Code);
            throw new InvalidDataException(ErrorMessages.KeyNotMatch);
        }
        
        var mod = await GetPermissionByCode(code);

        if (mod == null)
        {
            throw new NotFoundException();
        }

        _context.Permissions.Update(obj);
        await _uow.CompleteAsync();
        
        _logger.LogInformation("Permission {PermissionCode} updated successfully", code);
        return true;
    }

    public async Task<bool> DeletePermission(string code)
    {
        var obj = await GetPermissionByCode(code);
        if (obj == null)
        {
            throw new NotFoundException();
        }
        _context.Permissions.Remove(obj);
        await _uow.CompleteAsync();
        
        _logger.LogInformation("Permission {PermissionCode} deleted successfully", code);
        return true;
    }
    
    //roles
    private IQueryable<Role> CreateRoleQuery(bool includePermissions)
    {
        var query = _context.Roles.AsNoTracking();
        if (includePermissions)
        {
            query = query.Include(r => r.RolePermissions)!.ThenInclude(r => r.Permission);
        }
        return query;
    }
    
    public async Task<IEnumerable<Role>> GetAllRoles(bool includePermissions = false)
    {
        var query = CreateRoleQuery(includePermissions);
        return await query.ToListAsync();
    }

    public async Task<Role?> GetRoleById(string id, bool includePermissions = false)
    {
        var query = CreateRoleQuery(includePermissions).FirstOrDefaultAsync(r => r.Id == Guid.Parse(id));
        return await query;
    }
    
    public async Task<Role?> GetRoleByName(string name, bool includePermissions = false)
    {
        var query = CreateRoleQuery(includePermissions).FirstOrDefaultAsync(r => r.Name == name);
        return await query;
    }

    public async Task<Role> AddRole(Role obj)
    {
        _context.Roles.Add(obj);
        await _uow.CompleteAsync();
        
        _logger.LogInformation("Role {RoleName} created successfully with ID {RoleId}", obj.Name, obj.Id);
        return obj;
    }

    public async Task<bool> UpdateRole(string id, Role obj)
    {
        if (Guid.Parse(id) != obj.Id)
        {
            _logger.LogWarning("Invalid ID mismatch for role update: provided {ProvidedId}, object {ObjectId}", id, obj.Id);
            throw new InvalidDataException(ErrorMessages.KeyNotMatch);
        }
        
        var mod = await GetRoleById(id, false);

        if (mod == null)
        {
            throw new NotFoundException();
        }
        
        _context.Roles.Update(obj);
        await _uow.CompleteAsync();
        
        _logger.LogInformation("Role {RoleId} updated successfully", id);
        return true;
    }

    public async Task<bool> DeleteRole(string id)
    {
        var obj = await GetRoleById(id, true);
        if (obj == null)
        {
            throw new NotFoundException();
        }
        
        if (obj.RolePermissions != null && obj.RolePermissions.Count > 0)
        {
            throw new InvalidDataException("Cannot delete until all Permissions removed from Role");
        }
        
        _context.Roles.Remove(obj);
        await _uow.CompleteAsync();
        
        _logger.LogInformation("Role {RoleId} deleted successfully", id);
        return true;
    }

    public async Task<Role> AddPermissionsToRole(string roleId, string[] permissionCodes)
    {
        // Retrieve the role by its ID
        var role = await GetRoleById(roleId, false);

        if (role == null)
        {
            throw new NotFoundException($"Role with ID {roleId} does not exist.");
        }

        // Retrieve permissions based on the provided codes
        var permissions = await _context.Permissions
            .Where(p => permissionCodes.Contains(p.Code))
            .ToListAsync();

        if (permissions.Count != permissionCodes.Length)
        {
            throw new InvalidDataException("Some permissions do not exist or are invalid.");
        }

        // Validate RoleScope compatibility for all permissions using hierarchical rules
        var incompatiblePermissions = permissions
            .Where(p => !CanPermissionBeAssignedToRole(p.RoleScope, role.Scope))
            .ToList();
        
        if (incompatiblePermissions.Any())
        {
            var incompatibleCodes = string.Join(", ", incompatiblePermissions.Select(p => $"{p.Code} (scope: {p.RoleScope})"));
            throw new InvalidDataException($"The following permissions cannot be assigned to role with scope {role.Scope}: {incompatibleCodes}");
        }

        // Get existing role permissions to check for duplicates
        var existingRolePermissions = await _context.RolePermissions
            .Where(rp => rp.RoleId == Guid.Parse(roleId) && permissionCodes.Contains(rp.PermissionCode))
            .Select(rp => rp.PermissionCode)
            .ToListAsync();

        try
        {
            // Add permissions to the role (skip existing ones)
            foreach (var permission in permissions)
            {
                if (!existingRolePermissions.Contains(permission.Code))
                {
                    _context.RolePermissions.Add(new RolePermission
                    {
                        RoleId = Guid.Parse(roleId),
                        PermissionCode = permission.Code
                    });
                }
            }

            await _uow.CompleteAsync();

            // Invalidate cache since role permissions changed
            InvalidateRolePermissionCache();

            return (await GetRoleById(roleId, true))!;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error adding permissions to role {RoleId}", roleId);
            throw new ServiceException("Error adding permissions to role");
        }
    }

    public async Task<Role> AddPermissionToRole(string roleId, string permissionCode)
    {
        var role = await GetRoleById(roleId, false);
        if (role == null)
        {
            throw new NotFoundException($"Role with ID {roleId} does not exist.");
        }

        var permission = await GetPermissionByCode(permissionCode);
        if (permission == null)
        {
            throw new NotFoundException($"Permission with code {permissionCode} does not exist.");
        }

        // Validate RoleScope compatibility using hierarchical rules
        if (!CanPermissionBeAssignedToRole(permission.RoleScope, role.Scope))
        {
            throw new InvalidDataException($"Permission {permissionCode} (scope: {permission.RoleScope}) cannot be assigned to role with scope {role.Scope}.");
        }

        // Check if the role already has this permission
        var existingRolePermission = await _context.RolePermissions
            .FirstOrDefaultAsync(rp => rp.RoleId == Guid.Parse(roleId) && rp.PermissionCode == permissionCode);
        
        if (existingRolePermission != null)
        {
            throw new InvalidDataException($"Role already has permission {permissionCode}.");
        }

        try
        {
            _context.RolePermissions.Add(new RolePermission
            {
                RoleId = Guid.Parse(roleId),
                PermissionCode = permissionCode
            });

            await _uow.CompleteAsync();

            // Invalidate cache since role permissions changed
            InvalidateRolePermissionCache();

            return (await GetRoleById(roleId, true))!;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error adding permission {PermissionCode} to role {RoleId}", permissionCode, roleId);
            throw new ServiceException("Error adding permission to role");
        }
    }

    public async Task<Role> RemovePermissionFromRole(string roleId, string permissionCode)
    {
        var role = await GetRoleById(roleId, false);
        if (role == null)
        {
            throw new NotFoundException($"Role with ID {roleId} does not exist.");
        }

        var rolePermission = await _context.RolePermissions
            .FirstOrDefaultAsync(rp => rp.RoleId == Guid.Parse(roleId) && rp.PermissionCode == permissionCode);
        
        if (rolePermission == null)
        {
            throw new NotFoundException($"Role does not have permission {permissionCode}.");
        }

        try
        {
            _context.RolePermissions.Remove(rolePermission);
            await _uow.CompleteAsync();

            // Invalidate cache since role permissions changed
            InvalidateRolePermissionCache();

            return (await GetRoleById(roleId, true))!;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error removing permission {PermissionCode} from role {RoleId}", permissionCode, roleId);
            throw new ServiceException("Error removing permission from role");
        }
    }

    public async Task<List<CommonRolesPermission>> GetAllRolesWithPermissionsCached()
    {
        // Try to get from cache first
        var (success, cachedRoles) = await _cache.TryGetAsync<List<CommonRolesPermission>>(CommonConstants.PermissionRoleCacheKey);
        if (success && cachedRoles != null)
        {
            return cachedRoles;
        }

        // If not in cache, fetch data
        var rawRolesData = await GetAllRoles(true);
        
        var commonRoles = new List<CommonRolesPermission>();
        foreach (var authRole in rawRolesData)
        {
            var commonRole = new CommonRolesPermission
            {
                Id = authRole.Id.ToString(),
                Name = authRole.Name,
                Permissions = authRole.RolePermissions?.Select(rp => new CommonPermission
                {
                    Code = rp.Permission?.Code!
                }).ToList() ?? new List<CommonPermission>()
            };
            commonRoles.Add(commonRole);
        }
        
        // Cache the results for 10 minutes
        await _cache.SetAsync(CommonConstants.PermissionRoleCacheKey, commonRoles, TimeSpan.FromMinutes(10));
        
        return commonRoles;
    }

    public void InvalidateRolePermissionCache()
    {
        _ = Task.Run(async () => await _cache.RemoveAsync(CommonConstants.PermissionRoleCacheKey));
    }

    /// <summary>
    /// Checks if a permission can be assigned to a role based on hierarchical scope rules.
    /// Higher scope roles can have permissions from their scope and all lower scopes.
    /// Hierarchy: Internal(1) -> Tenant(2) -> Site(4) -> Default(8)
    /// Null permissions can be assigned to any role.
    /// </summary>
    /// <param name="permissionScope">The scope of the permission (can be null)</param>
    /// <param name="roleScope">The scope of the role</param>
    /// <returns>True if the permission can be assigned to the role</returns>
    public static bool CanPermissionBeAssignedToRole(RoleScope? permissionScope, RoleScope roleScope)
    {
        // Null permissions can be assigned to any role
        if (!permissionScope.HasValue)
        {
            return true;
        }

        // Get the hierarchical level for comparison
        var permissionLevel = GetScopeHierarchyLevel(permissionScope.Value);
        var roleLevel = GetScopeHierarchyLevel(roleScope);

        // Higher scope roles (lower level numbers) can have permissions from their scope and all lower scopes
        return roleLevel <= permissionLevel;
    }

    /// <summary>
    /// Gets the hierarchical level of a scope for comparison.
    /// Lower numbers = higher in hierarchy (more permissions).
    /// </summary>
    /// <param name="scope">The role scope</param>
    /// <returns>Hierarchical level (1=Internal, 2=Tenant, 3=Site, 4=Default)</returns>
    private static int GetScopeHierarchyLevel(RoleScope scope)
    {
        return scope switch
        {
            RoleScope.Internal => 1, // Highest level - can have all permissions
            RoleScope.Tenant => 2,   // Can have Tenant, Site, Default permissions
            RoleScope.Site => 3,     // Can have Site, Default permissions  
            RoleScope.Default => 4,  // Lowest level - can only have Default permissions
            _ => int.MaxValue        // Unknown scopes get lowest priority
        };
    }
    
}