using System.Security.Claims;
using System.Text.Json;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Caching.Memory;
using NetStarterCommon.Core.Common.Constants;
using NetStarterCommon.Core.Common.Models;
using NetStarterCommon.Core.Common.Permissions;
using PlatformApi.Services;

namespace PlatformApi;

public class PermissionsAuthServerMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ILogger<PermissionsAuthServerMiddleware> _logger;
    private readonly IServiceScopeFactory _serviceScopeFactory;
    private readonly IMemoryCache _cache;
    private readonly List<string> _excludedPaths;

    public PermissionsAuthServerMiddleware(RequestDelegate next, ILogger<PermissionsAuthServerMiddleware> logger, 
        IServiceScopeFactory serviceScopeFactory,IMemoryCache cache)
    {
        _next = next;
        _logger = logger;
        _serviceScopeFactory = serviceScopeFactory;
        _cache = cache;
        
        _excludedPaths = new List<string>
        {
            "/health",
            "/swagger"
        };
    }
    
    public async Task InvokeAsync(HttpContext context)
    {
        if (_excludedPaths.Any(path => context.Request.Path.StartsWithSegments(path)))
        {
            await _next(context); // Skip middleware for this path
            return;
        }
        var endpoint = context.GetEndpoint();
        if (endpoint?.Metadata?.GetMetadata<IAllowAnonymous>() != null)
        {
            await _next(context);
            return;
        }
        
        if (context.User.Identity?.IsAuthenticated == true)
        {
            var token = await GetAuthTokenAsync(context); // Fetch current token
            
            var userRoles = GetRolesFromClaims(context);
            
            // Get all roles with permissions (cached)
            var allRolesWithPermissions = await GetAllRolesWithPermissions(token);
            
            // Extract permissions for user's roles
            var userPermissions = ExtractPermissionsForUserRoles(userRoles, allRolesWithPermissions);
            
            context.Items[PermissionConstants.PermissionContext] = userPermissions;
        }
        
        await _next(context);
    }
    
    private List<string> GetRolesFromClaims(HttpContext context)
    {
        var roles = new List<string>();
    
        // Debug logging to see what's actually in the claims
        var allClaims = context.User.Claims
            .Where(c =>  c.Type == ClaimTypes.Role ||  c.Type == CommonConstants.RolesClaim || c.Type == CommonConstants.AdminRolesClaim)
            .ToList();
        
        foreach (var claim in allClaims)
        {
            _logger.LogDebug("Found claim: Type={ClaimType}, Value={ClaimValue}", claim.Type, claim.Value);
        }
    
        // Try different approaches based on what we see
        foreach (var claim in allClaims)
        {
            try
            {
                // If the claim is already a single role (not JSON)
                if (!claim.Value.TrimStart().StartsWith("["))
                {
                    roles.Add(claim.Value);
                    continue;
                }
            
                // Try deserializing as array
                var rolesArray = JsonSerializer.Deserialize<string[]>(claim.Value);
                if (rolesArray != null && rolesArray.Length > 0)
                {
                    roles.AddRange(rolesArray);
                }
            }
            catch (JsonException ex)
            {
                _logger.LogError(ex, "Error parsing roles claim: {ClaimType} = {ClaimValue}", 
                    claim.Type, claim.Value);
            }
        }
    
        return roles.Distinct().ToList();
    }
    
    private async Task<List<CommonRolesPermission>> GetAllRolesWithPermissions(string token)
    {
        // Try to get from cache first
        if (_cache.TryGetValue(CommonConstants.PermissionRoleCacheKey, out List<CommonRolesPermission>? cachedRoles))
        {
            return cachedRoles!;
        }
        
        try
        {

            using (var scope = _serviceScopeFactory.CreateScope())
            {
                var allRoles = new List<CommonRolesPermission>();
                var permissionService = scope.ServiceProvider.GetRequiredService<IPermissionService>();
                var rawRolesData = await permissionService.GetAllRoles(true);

                foreach (var authRole in rawRolesData)
                {
                    var commonRole = new CommonRolesPermission
                    {
                        Id = authRole.Id.ToString(),
                        Name = authRole.Name,
                        Permissions = authRole.RolePermissions?.Select(rp => new CommonPermission
                        {
                            Code = rp.Permission?.Code!,
                            // Add other Permission properties as needed
                        }).ToList() ?? new List<CommonPermission>(),
                    };

                    allRoles.Add(commonRole);
                }

                if (allRoles.Any())
                {
                    // Cache the results
                    var cacheOptions = new MemoryCacheEntryOptions()
                        .SetAbsoluteExpiration(TimeSpan.FromMinutes(10));

                    _cache.Set(CommonConstants.PermissionRoleCacheKey, allRoles, cacheOptions);

                    return allRoles;
                }

                _logger.LogWarning("Failed to fetch role permissions");
                throw new ServiceException("Failed to fetch role permissions");
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error fetching role permissions");
            throw;
        }
    }
    
    private List<CommonPermission> ExtractPermissionsForUserRoles(List<string> userRoles, List<CommonRolesPermission> allRoles)
    {
        // Filter roles that match the user's roles and extract unique permissions
        var permissions = allRoles
            .Where(r => r.Name != null && userRoles.Contains(r.Name, StringComparer.OrdinalIgnoreCase))
            .SelectMany(r => r.Permissions ?? new List<CommonPermission>())
            .Select(p => new CommonPermission { Code = p.Code })
            .GroupBy(p => p.Code)
            .Select(g => g.First())
            .ToList();
        
        return permissions;
    }
    
    private async Task<string> GetAuthTokenAsync(HttpContext context)
    {
        var token = await Task.FromResult(context.Request.Headers["Authorization"]
            .ToString()
            .Replace("Bearer ", string.Empty));

        return token;
    }
}