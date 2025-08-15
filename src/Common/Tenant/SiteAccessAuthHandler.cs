using Microsoft.AspNetCore.Authorization;
using PlatformApi.Common.Constants;

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
    private readonly ILogger<SiteAccessAuthHandler> _logger;

    public SiteAccessAuthHandler(ILogger<SiteAccessAuthHandler> logger)
    {
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    protected override Task HandleRequirementAsync(
        AuthorizationHandlerContext context,
        SiteAccessRequirement requirement)
    {
        // Check if user is authenticated
        if (!context.User.Identity?.IsAuthenticated ?? true)
        {
            _logger.LogWarning("SiteCheck - User is not authenticated");
            context.Fail(new AuthorizationFailureReason(this, "User is not authenticated"));
        }
        else
        {
            // Get site from JWT claims
            var siteIdClaim = context.User.FindFirst(CommonConstants.ActiveSiteClaim);
            if (siteIdClaim == null || string.IsNullOrWhiteSpace(siteIdClaim.Value) || !Guid.TryParse(siteIdClaim.Value, out _))
            {
                _logger.LogWarning("No valid site claim found in JWT");
                context.Fail(new AuthorizationFailureReason(this, "No valid site claim found"));
            }
            else
            {
                // JWT already validated site access, so we can succeed
                context.Succeed(requirement);
            }
        }

        return Task.CompletedTask;
    }
}