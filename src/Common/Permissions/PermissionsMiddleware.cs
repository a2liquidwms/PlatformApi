using System.IdentityModel.Tokens.Jwt;
using System.Text.Json;
using Microsoft.Extensions.Caching.Memory;
using PlatformApi.Common.Auth;
using PlatformApi.Common.Constants;

namespace PlatformApi.Common.Permissions;

public class PermissionsMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ILogger<PermissionsMiddleware> _logger;
    private readonly IMemoryCache _cache;
    private readonly HttpClient _httpClient;

    public PermissionsMiddleware(RequestDelegate next, ILogger<PermissionsMiddleware> logger, 
        IHttpClientFactory httpClientFactory, IMemoryCache cache)
    {
        _next = next;
        _logger = logger;
        _cache = cache;
        _httpClient = httpClientFactory.CreateClient("PermissionApiClient");
        
    }

    public async Task InvokeAsync(HttpContext context)
    {
        
        if (context.User.Identity?.IsAuthenticated == true)
        {
            var userId = context.User.FindFirst(JwtRegisteredClaimNames.Sub)?.Value ?? throw new InvalidOperationException();
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
            .Where(c => c.Type == CommonConstants.RolesClaim)
            .ToList();
    
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
        
        // If not in cache, fetch from API
        try
        {
            var requestUri = "/api/v1/admin/permission/roles?includePermissions=true";
            var request = new HttpRequestMessage(HttpMethod.Get, requestUri);
            request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", token);
            
            var response = await _httpClient.SendAsync(request);

            var options = new JsonSerializerOptions
            {
                PropertyNameCaseInsensitive = true,
                DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull
            };
            
            if (response.IsSuccessStatusCode)
            {
                var responseContent = await response.Content.ReadAsStringAsync();
                var allRoles = JsonSerializer.Deserialize<List<CommonRolesPermission>>(responseContent, options);
                
                if (allRoles != null)
                {
                    // Cache the results
                    var cacheOptions = new MemoryCacheEntryOptions()
                        .SetAbsoluteExpiration(TimeSpan.FromMinutes(10));
                    
                    _cache.Set(CommonConstants.PermissionRoleCacheKey, allRoles, cacheOptions);
                    
                    return allRoles;
                }
            }

            _logger.LogWarning("Failed to fetch role permissions. Status: {StatusCode}", response.StatusCode);
            throw new ServiceException("Failed to fetch role permissions");
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