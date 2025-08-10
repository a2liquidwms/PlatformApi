using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using PlatformApi.Common.Constants;

namespace PlatformApi.Common.Auth;

public class UserHelper
{
    private readonly IHttpContextAccessor _httpContextAccessor;
    private readonly ILogger<UserHelper> _logger;

    public UserHelper(IHttpContextAccessor httpContextAccessor, ILogger<UserHelper> logger)
    {
        _httpContextAccessor = httpContextAccessor;
        _logger = logger;
    }

    public string? GetCurrentUserEmail()
    {
        return _httpContextAccessor.HttpContext?.User.FindFirstValue(JwtRegisteredClaimNames.Email);
    }

    public Guid GetCurrentUserId()
    {
        var userIdString = _httpContextAccessor.HttpContext?.User.FindFirstValue(CommonConstants.ClaimUserId);
        
        if (string.IsNullOrEmpty(userIdString))
        {
            throw new UnauthorizedAccessException("User ID not found in token claims");
        }
        
        if (!Guid.TryParse(userIdString, out var userId))
        {
            _logger.LogWarning("Invalid User ID format in claims: {UserId}", userIdString);
            throw new InvalidDataException("Invalid User ID format in claims");
        }
        
        return userId;
    }

    public bool IsUserAuthenticated()
    {
        return _httpContextAccessor.HttpContext?.User.Identity?.IsAuthenticated ?? false;
    }
}