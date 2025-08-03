using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using NetStarterCommon.Core.Common.Constants;

namespace NetStarterCommon.Core.Common.Tenant;

public class TenantMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ILogger<TenantMiddleware> _logger;

    public TenantMiddleware(RequestDelegate next, ILogger<TenantMiddleware> logger)
    {
        _next = next ?? throw new ArgumentNullException(nameof(next));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    public async Task InvokeAsync(HttpContext context)
    {
        try
        {
            // Extract tenant ID from header
            if (context.Request.Headers.TryGetValue(CommonConstants.TenantHeaderKey, out var tenantIdValue) && 
                !string.IsNullOrWhiteSpace(tenantIdValue))
            {
                // Validate GUID format
                if (Guid.TryParse(tenantIdValue, out var tenantId))
                {
                    // Set tenant context
                    context.Items[CommonConstants.TenantHttpContext] = tenantId;
                    _logger.LogDebug("Tenant context set for tenant: {TenantId}", tenantId);
                }
                else
                {
                    _logger.LogWarning("Invalid tenant ID format in header: {TenantId}", tenantIdValue!);
                }
            }
            else
            {
                _logger.LogDebug("No tenant header found for request: {Path}", context.Request.Path);
            }

            // Always continue to next middleware
            await _next(context);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Unexpected error in TenantMiddleware");
            throw;
        }
    }
}