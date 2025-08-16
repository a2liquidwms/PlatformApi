using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;
using NetStarterCommon.Core.Common.Models;
using PlatformApi.Common.Constants;
using PlatformApi.Common.Services;
using PlatformApi.Data;
using PlatformApi.Models;

namespace PlatformApi.Services;

public class PermissionService : IPermissionService
{
    private readonly ILogger<PermissionService> _logger;
    private readonly PlatformDbContext _context;
    private readonly IUnitOfWork<PlatformDbContext> _uow;
    private readonly ITenantService _tenantService;
    private readonly IMemoryCache _cache;

    public PermissionService(ILogger<PermissionService> logger, PlatformDbContext context, IUnitOfWork<PlatformDbContext> uow,
        ITenantService tenantService, IMemoryCache cache)
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
        return obj;
    }
    
    public async Task<int> AddPermissionsMulti(Permission[] objs)
    {
        var count = 0;
        try
        {
            
            foreach (var perm in objs)
            {
                _context.Permissions.Add(perm);
                count++;
            }
            await _uow.CompleteAsync();
            return count;
        }
        catch (Exception ex)
        {
            var message = ex.InnerException!.Message ?? "Error saving Permissions";
            _logger.LogError(ex, message);
            throw new ArgumentException(message);
        }
    }

    public async Task<bool> UpdatePermission(string code, Permission obj)
    {
        if (code != obj.Code)
        {
            _logger.LogInformation("Invalid Code: {Code}", code);
            throw new InvalidDataException(ErrorMessages.KeyNotMatch);
        }
        
        var mod = await GetPermissionByCode(code);

        if (mod == null)
        {
            throw new NotFoundException();
        }

        _context.Permissions.Update(obj);
        await _uow.CompleteAsync();
        return true;
    }

    public async Task<bool> DeletePermission(string code)
    {
        var obj = await GetPermissionByCode(code);
        if (obj == null)
        {
            _logger.LogInformation("Not Found, Code: {Code}", code);
            throw new NotFoundException();
        }
        _context.Permissions.Remove(obj);
        await _uow.CompleteAsync();
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
        return obj;
    }

    public async Task<bool> UpdateRole(string id, Role obj)
    {
        if (Guid.Parse(id) != obj.Id)
        {
            _logger.LogInformation("Invalid Id: {Id}", id);
            throw new InvalidDataException(ErrorMessages.KeyNotMatch);
        }
        
        var mod = await GetRoleById(id, false);

        if (mod == null)
        {
            throw new NotFoundException();
        }
        
        _context.Roles.Update(obj);
        await _uow.CompleteAsync();
        return true;
    }

    public async Task<bool> DeleteRole(string id)
    {
        var obj = await GetRoleById(id, true);
        if (obj == null)
        {
            _logger.LogInformation("Not Found, Id: {Id}", id);
            throw new NotFoundException();
        }
        
        if (obj.RolePermissions != null && obj.RolePermissions.Count > 0)
        {
            throw new InvalidDataException("Cannot delete until all Permissions removed from Role");
        }
        
        _context.Roles.Remove(obj);
        await _uow.CompleteAsync();
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

        // Validate RoleScope compatibility for all permissions
        var incompatiblePermissions = permissions
            .Where(p => p.RoleScope.HasValue && p.RoleScope != role.Scope)
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

        // Validate RoleScope compatibility
        if (permission.RoleScope.HasValue && permission.RoleScope != role.Scope)
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
        if (_cache.TryGetValue(CommonConstants.PermissionRoleCacheKey, out List<CommonRolesPermission>? cachedRoles))
        {
            return cachedRoles!;
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
        var cacheOptions = new MemoryCacheEntryOptions()
            .SetAbsoluteExpiration(TimeSpan.FromMinutes(10));
        
        _cache.Set(CommonConstants.PermissionRoleCacheKey, commonRoles, cacheOptions);
        
        return commonRoles;
    }

    public void InvalidateRolePermissionCache()
    {
        _cache.Remove(CommonConstants.PermissionRoleCacheKey);
    }
    
}