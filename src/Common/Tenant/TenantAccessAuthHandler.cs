using System.Security.Claims;
using System.Text.Json;
using Microsoft.AspNetCore.Authorization;
using NetStarterCommon.Core.Common.Models;
using PlatformApi.Common.Constants;

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

    public TenantAccessAuthHandler(
        IHttpContextAccessor httpContextAccessor,
        ILogger<TenantAccessAuthHandler> logger)
    {
        _httpContextAccessor = httpContextAccessor ?? throw new ArgumentNullException(nameof(httpContextAccessor));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    protected override Task HandleRequirementAsync(
        AuthorizationHandlerContext context,
        TenantAccessRequirement requirement)
    {
        var httpContext = _httpContextAccessor.HttpContext;

        // Check if user is authenticated
        if (!context.User.Identity?.IsAuthenticated ?? true)
        {
            _logger.LogWarning("TenantCheck - User is not authenticated");
            context.Fail(new AuthorizationFailureReason(this, "User is not authenticated"));
            return Task.CompletedTask;
        }

        // Get tenant from context (set by middleware)
        if (!httpContext!.Items.TryGetValue(CommonConstants.TenantHttpContext, out var tenantObj) ||
            tenantObj is not Guid tenantId)
        {
            _logger.LogWarning("No tenant set");
            context.Fail(new AuthorizationFailureReason(this, "No tenant set"));
            return Task.CompletedTask;
        }

        // Check if user has access to this tenant via JWT claims
        if (UserHasAccessToTenant(context.User, tenantId))
        {
            context.Succeed(requirement);
        }
        else
        {
            _logger.LogWarning("User {UserId} does not have access to tenant {TenantId}",
                context.User.FindFirst(CommonConstants.ClaimUserId)?.Value, tenantId);
            context.Fail(new AuthorizationFailureReason(this, "No Tenant Access"));
        }

        return Task.CompletedTask;
    }

    private bool UserHasAccessToTenant(ClaimsPrincipal user, Guid tenantId)
    {
        // Get all claims for the tenants
        var tenantClaims = user.Claims.Where(c => c.Type == CommonConstants.TenantsClaim);
        foreach (var claim in tenantClaims)
        {
            try
            {
                // Try deserializing the claim value as a JSON array of tenant objects
                var tenants = JsonSerializer.Deserialize<List<TenantInfo>>(claim.Value);
                if (tenants != null && tenants.Any(t =>
                        string.Equals(t.Id, tenantId)))
                {
                    return true;
                }
            }
            catch (JsonException)
            {
                var claimText = JsonSerializer.Deserialize<TenantInfo>(claim.Value);
                if (claimText?.Id != null)
                {
                    // Fallback: if the claim isn't JSON, compare the raw string value
                    if (claimText.Id.Equals(tenantId))
                    {
                        return true;
                    }
                }
            }
        }

        return false;
    }
}