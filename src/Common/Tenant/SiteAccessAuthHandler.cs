using Microsoft.AspNetCore.Authorization;
using PlatformApi.Common.Auth;
using PlatformApi.Common.Constants;
using PlatformApi.Services;

namespace PlatformApi.Common.Tenant;

/// <summary>
/// Authorization requirement that validates authenticated users have access to the current site
/// </summary>
public class SiteAccessRequirement : IAuthorizationRequirement
{
}

[AttributeUsage(AttributeTargets.Class | AttributeTargets.Method, AllowMultiple = false, Inherited = true)]
public class RequireSiteAccessAttribute : AuthorizeAttribute
{
    public RequireSiteAccessAttribute() 
    {
        Policy = "RequireSiteAccess"; 
    }
}

public class SiteAccessAuthHandler : AuthorizationHandler<SiteAccessRequirement>
{
    private readonly IHttpContextAccessor _httpContextAccessor;
    private readonly ILogger<SiteAccessAuthHandler> _logger;
    private readonly UserHelper _userHelper;
    private readonly IUserService _userService;

    public SiteAccessAuthHandler(
        IHttpContextAccessor httpContextAccessor,
        ILogger<SiteAccessAuthHandler> logger,
        UserHelper userHelper,
        IUserService userService)
    {
        _httpContextAccessor = httpContextAccessor ?? throw new ArgumentNullException(nameof(httpContextAccessor));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _userHelper = userHelper ?? throw new ArgumentNullException(nameof(userHelper));
        _userService = userService ?? throw new ArgumentNullException(nameof(userService));
    }

    protected override async Task HandleRequirementAsync(
        AuthorizationHandlerContext context,
        SiteAccessRequirement requirement)
    {
        var httpContext = _httpContextAccessor.HttpContext;

        // Check if user is authenticated
        if (!context.User.Identity?.IsAuthenticated ?? true)
        {
            _logger.LogWarning("SiteCheck - User is not authenticated");
            context.Fail(new AuthorizationFailureReason(this, "User is not authenticated"));
            return;
        }

        // Get tenant from context (required for site validation)
        if (!httpContext!.Items.TryGetValue(CommonConstants.TenantHttpContext, out var tenantObj) ||
            tenantObj is not Guid tenantId)
        {
            _logger.LogWarning("No tenant set - required for site access validation");
            context.Fail(new AuthorizationFailureReason(this, "No tenant set"));
            return;
        }

        // Get site from context (set by middleware)
        if (!httpContext.Items.TryGetValue(CommonConstants.SiteHttpContext, out var siteObj) ||
            siteObj is not Guid siteId)
        {
            _logger.LogWarning("No site set");
            context.Fail(new AuthorizationFailureReason(this, "No site set"));
            return;
        }

        // Check if user has access to this site via database lookup
        var userId = _userHelper.GetCurrentUserId();
        var hasAccess = await _userService.HasSiteAccess(userId, siteId, tenantId);
        
        if (hasAccess)
        {
            context.Succeed(requirement);
        }
        else
        {
            _logger.LogWarning("User {UserId} does not have access to site {SiteId} in tenant {TenantId}", userId, siteId, tenantId);
            context.Fail(new AuthorizationFailureReason(this, "No Site Access"));
        }
    }
}