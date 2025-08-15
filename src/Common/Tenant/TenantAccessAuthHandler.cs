using Microsoft.AspNetCore.Authorization;
using PlatformApi.Common.Constants;

namespace PlatformApi.Common.Tenant;

/// <summary>
/// Authorization requirement that validates authenticated users have access to the current tenant
/// </summary>
public class TenantAccessRequirement : IAuthorizationRequirement
{
}

public class RequireTenantAccessAttribute : AuthorizeAttribute
{
    public RequireTenantAccessAttribute() 
    {
        Policy = "RequireTenantAccess"; 
    }
}

public class TenantAccessAuthHandler : AuthorizationHandler<TenantAccessRequirement>
{
    private readonly ILogger<TenantAccessAuthHandler> _logger;

    public TenantAccessAuthHandler(ILogger<TenantAccessAuthHandler> logger)
    {
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    protected override Task HandleRequirementAsync(
        AuthorizationHandlerContext context,
        TenantAccessRequirement requirement)
    {
        // Check if user is authenticated
        if (!context.User.Identity?.IsAuthenticated ?? true)
        {
            _logger.LogWarning("TenantCheck - User is not authenticated");
            context.Fail(new AuthorizationFailureReason(this, "User is not authenticated"));
        }
        else
        {
            // Get tenant from JWT claims
            var tenantIdClaim = context.User.FindFirst(CommonConstants.ActiveTenantClaim);
            if (tenantIdClaim == null || string.IsNullOrWhiteSpace(tenantIdClaim.Value) || !Guid.TryParse(tenantIdClaim.Value, out _))
            {
                _logger.LogWarning("No valid tenant claim found in JWT");
                context.Fail(new AuthorizationFailureReason(this, "No valid tenant claim found"));
            }
            else
            {
                // JWT already validated tenant access, so we can succeed
                context.Succeed(requirement);
            }
        }

        return Task.CompletedTask;
    }

}