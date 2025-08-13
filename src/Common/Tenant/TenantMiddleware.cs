using PlatformApi.Common.Constants;

namespace PlatformApi.Common.Tenant;

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
            // Note: Tenant resolution is now handled via JWT claims in TenantHelper
            // This middleware is kept for potential future use (e.g., subdomain extraction)
            // or can be removed entirely if no longer needed
            
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