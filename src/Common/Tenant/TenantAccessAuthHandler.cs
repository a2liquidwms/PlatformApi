using Microsoft.AspNetCore.Authorization;
using PlatformApi.Common.Auth;
using PlatformApi.Common.Constants;
using PlatformApi.Services;

namespace PlatformApi.Common.Tenant;

/// <summary>
/// Authorization requirement that validates authenticated users have access to the current tenant
/// </summary>
public class TenantAccessRequirement : IAuthorizationRequirement
{
}

public class TenantAccessAuthHandler : AuthorizationHandler<TenantAccessRequirement>
{
    private readonly IHttpContextAccessor _httpContextAccessor;
    private readonly ILogger<TenantAccessAuthHandler> _logger;
    private readonly UserHelper _userHelper;
    private readonly ITenantService _tenantService;

    public TenantAccessAuthHandler(
        IHttpContextAccessor httpContextAccessor,
        ILogger<TenantAccessAuthHandler> logger,
        UserHelper userHelper,
        ITenantService tenantService)
    {
        _httpContextAccessor = httpContextAccessor ?? throw new ArgumentNullException(nameof(httpContextAccessor));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _userHelper = userHelper ?? throw new ArgumentNullException(nameof(userHelper));
        _tenantService = tenantService ?? throw new ArgumentNullException(nameof(tenantService));
    }

    protected override async Task HandleRequirementAsync(
        AuthorizationHandlerContext context,
        TenantAccessRequirement requirement)
    {
        var httpContext = _httpContextAccessor.HttpContext;

        // Check if user is authenticated
        if (!context.User.Identity?.IsAuthenticated ?? true)
        {
            _logger.LogWarning("TenantCheck - User is not authenticated");
            context.Fail(new AuthorizationFailureReason(this, "User is not authenticated"));
            return;
        }

        // Get tenant from context (set by middleware)
        if (!httpContext!.Items.TryGetValue(CommonConstants.TenantHttpContext, out var tenantObj) ||
            tenantObj is not Guid tenantId)
        {
            _logger.LogWarning("No tenant set");
            context.Fail(new AuthorizationFailureReason(this, "No tenant set"));
            return;
        }

        // Check if user has access to this tenant via database lookup
        var userId = _userHelper.GetCurrentUserId();
        var hasAccess = await _tenantService.HasTenantAccess(userId, tenantId);
        
        if (hasAccess)
        {
            context.Succeed(requirement);
        }
        else
        {
            _logger.LogWarning("User {UserId} does not have access to tenant {TenantId}", userId, tenantId);
            context.Fail(new AuthorizationFailureReason(this, "No Tenant Access"));
        }
    }

}