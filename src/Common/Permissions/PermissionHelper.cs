using PlatformApi.Common.Auth;

namespace PlatformApi.Common.Permissions;

public class PermissionHelper
{
    private readonly IHttpContextAccessor _httpContextAccessor;
    private readonly ILogger<PermissionHelper> _logger;

    public PermissionHelper(IHttpContextAccessor httpContextAccessor, ILogger<PermissionHelper> logger)
    {
        _httpContextAccessor = httpContextAccessor;
        _logger = logger;
    }

    public bool HasPermission(string permission)
    {
        if (string.IsNullOrEmpty(permission))
        {
            _logger.LogWarning("Permission check called with null or empty permission");
            return false;
        }

        var user = _httpContextAccessor.HttpContext?.User;
        if (user?.Identity?.IsAuthenticated != true)
        {
            _logger.LogWarning("Permission check called for unauthenticated user");
            return false;
        }

        var userPermissions = _httpContextAccessor.HttpContext?.Items[PermissionConstants.PermissionContext] as List<CommonPermission>;
        if (userPermissions == null || !userPermissions.Any())
        {
            _logger.LogDebug("No permissions found for user");
            return false;
        }

        var hasPermission = userPermissions.Any(p => p.Code == permission);
        _logger.LogDebug("Permission check for '{Permission}': {Result}", permission, hasPermission);
        
        return hasPermission;
    }
    
}