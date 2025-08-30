using Microsoft.AspNetCore.Authorization;

namespace PlatformApi.Common.Tenant;

public static class TenantStartupExtensions
{
    public static void TenantCheckServices(this IServiceCollection services, IConfiguration configuration)
    {
        services.AddScoped<IAuthorizationHandler, TenantAccessAuthHandler>();
        services.AddScoped<IAuthorizationHandler, SiteAccessAuthHandler>();
        services.AddScoped<TenantHelper>();

        services.AddAuthorization(options =>
        {
            options.AddPolicy("RequireTenantAccess", policy =>
                policy.Requirements.Add(new TenantAccessRequirement()));

            // New policy - checks if authenticated user has access to site
            options.AddPolicy("RequireSiteAccess", policy =>
                policy.Requirements.Add(new SiteAccessRequirement()));
        });
    }

    public static WebApplication ConfigureTenantMiddleware(this WebApplication app)
    {
        return app;
    }
}