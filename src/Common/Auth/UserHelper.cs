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

    public string? GetCurrentUserId()
    {
        return _httpContextAccessor.HttpContext?.User.FindFirstValue(CommonConstants.ClaimUserId);
    }

    public bool IsUserAuthenticated()
    {
        return _httpContextAccessor.HttpContext?.User.Identity?.IsAuthenticated ?? false;
    }
}