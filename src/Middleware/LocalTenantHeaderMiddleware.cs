using PlatformApi.Common.Tenant;

namespace PlatformApi.Middleware;

public class LocalTenantHeaderMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ILogger<LocalTenantHeaderMiddleware> _logger;
    private readonly bool _isDevelopment;

    public LocalTenantHeaderMiddleware(RequestDelegate next, ILogger<LocalTenantHeaderMiddleware> logger, IWebHostEnvironment environment)
    {
        _next = next;
        _logger = logger;
        _isDevelopment = environment.IsDevelopment();
    }

    public async Task InvokeAsync(HttpContext context)
    {
        // Only run in development environment
        if (_isDevelopment && context.Request.Path.StartsWithSegments("/auth"))
        {
            // Check for tenant parameter in query string for local testing
            var tenantParam = context.Request.Query["tenant"].FirstOrDefault();
            
            if (!string.IsNullOrEmpty(tenantParam))
            {
                // Add the tenant header that would normally come from nginx
                context.Request.Headers["X-Tenant-Subdomain"] = tenantParam;
                _logger.LogInformation("Local development: Set tenant subdomain to {TenantSubdomain} for auth page", tenantParam);
            }
        }

        await _next(context);
    }
}