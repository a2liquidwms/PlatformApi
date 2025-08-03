using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using NetStarterCommon.Core.Common.Constants;

namespace NetStarterCommon.Core.Common.Tenant;

public class RequireTenantAttribute : AuthorizeAttribute
{
    public RequireTenantAttribute()
    {
        Policy = "RequireTenant"; 
    }
}

[AttributeUsage(AttributeTargets.Class | AttributeTargets.Method, AllowMultiple = false, Inherited = true)]
public class RequireTenantAccessAttribute : AuthorizeAttribute
{
    public RequireTenantAccessAttribute() 
    {
        Policy = "RequireTenantAccess"; 
    }
}

public class TenantRequirement : IAuthorizationRequirement
{
}

public class TenantAuthHandler : AuthorizationHandler<TenantRequirement>
{
    private readonly IHttpContextAccessor _httpContextAccessor;
    private readonly ILogger<TenantAuthHandler> _logger;

    public TenantAuthHandler(
        IHttpContextAccessor httpContextAccessor,
        ILogger<TenantAuthHandler> logger)
    {
        _httpContextAccessor = httpContextAccessor ?? throw new ArgumentNullException(nameof(httpContextAccessor));
        _logger = logger;
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    protected override Task HandleRequirementAsync(
        AuthorizationHandlerContext context,
        TenantRequirement requirement)
    {
        var httpContext = _httpContextAccessor.HttpContext;

        // Check if tenant context exists
        if (httpContext!.Items.TryGetValue(CommonConstants.TenantHttpContext, out var tenantObj) && 
            tenantObj is Guid tenantId)
        {
            context.Succeed(requirement);
        }
        else
        {
            _logger.LogWarning("Tenant requirement failed - no tenant context found");
            context.Fail(new AuthorizationFailureReason(this, "No tenant header set"));
        }

        return Task.CompletedTask;
    }
}