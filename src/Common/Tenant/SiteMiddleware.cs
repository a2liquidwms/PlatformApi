using Microsoft.EntityFrameworkCore;
using PlatformApi.Common.Constants;
using PlatformApi.Data;
using System.Security.Claims;

namespace PlatformApi.Common.Tenant;

public class SiteMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ILogger<SiteMiddleware> _logger;
    private readonly IServiceScopeFactory _serviceScopeFactory;

    public SiteMiddleware(RequestDelegate next, ILogger<SiteMiddleware> logger, IServiceScopeFactory serviceScopeFactory)
    {
        _next = next ?? throw new ArgumentNullException(nameof(next));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _serviceScopeFactory = serviceScopeFactory ?? throw new ArgumentNullException(nameof(serviceScopeFactory));
    }

    public async Task InvokeAsync(HttpContext context)
    {
        try
        {
            // Extract site ID from JWT claims (if user is authenticated)
            if (context.User?.Identity?.IsAuthenticated == true)
            {
                var siteIdClaim = context.User.FindFirst(CommonConstants.ActiveSiteClaim);
                if (siteIdClaim != null && !string.IsNullOrWhiteSpace(siteIdClaim.Value))
                {
                    // Validate GUID format
                    if (Guid.TryParse(siteIdClaim.Value, out var siteId))
                    {
                        // Validate site exists and belongs to current tenant (if tenant context exists)
                        if (await ValidateSiteContext(context, siteId))
                        {
                            // Set site context
                            context.Items[CommonConstants.SiteHttpContext] = siteId;
                            _logger.LogDebug("Site context set from JWT claim for site: {SiteId}", siteId);
                        }
                        else
                        {
                            _logger.LogWarning("Invalid site context - site {SiteId} from JWT claim not found or doesn't belong to current tenant", siteId);
                        }
                    }
                    else
                    {
                        _logger.LogWarning("Invalid site ID format in JWT claim: {SiteId}", siteIdClaim.Value);
                    }
                }
                else
                {
                    _logger.LogDebug("No active site claim found in JWT for request: {Path}", context.Request.Path);
                }
            }
            else
            {
                _logger.LogDebug("User not authenticated, skipping site context extraction for request: {Path}", context.Request.Path);
            }

            // Always continue to next middleware
            await _next(context);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Unexpected error in SiteMiddleware");
            throw;
        }
    }

    private async Task<bool> ValidateSiteContext(HttpContext context, Guid siteId)
    {
        using var scope = _serviceScopeFactory.CreateScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<PlatformDbContext>();

        // Check if site exists
        var site = await dbContext.Sites
            .AsNoTracking()
            .FirstOrDefaultAsync(s => s.Id == siteId);

        if (site == null)
        {
            _logger.LogWarning("Site {SiteId} not found", siteId);
            return false;
        }

        // If tenant context exists, verify site belongs to that tenant
        if (context.Items.TryGetValue(CommonConstants.TenantHttpContext, out var tenantObj) && 
            tenantObj is Guid tenantId)
        {
            if (site.TenantId != tenantId)
            {
                _logger.LogWarning("Site {SiteId} does not belong to tenant {TenantId}", siteId, tenantId);
                return false;
            }
        }

        return true;
    }
}