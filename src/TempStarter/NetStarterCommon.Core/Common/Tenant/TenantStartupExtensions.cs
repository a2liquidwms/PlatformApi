using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace NetStarterCommon.Core.Common.Tenant;

public static class TenantStartupExtensions
{
    public static void TenantCheckServices(this IServiceCollection services, IConfiguration configuration)
    {
        services.AddSingleton<IAuthorizationHandler, TenantAuthHandler>();
        services.AddSingleton<IAuthorizationHandler, TenantAccessAuthHandler>();
        services.AddScoped<TenantHelper>();

        services.AddAuthorization(options =>
        {
            options.AddPolicy("RequireTenant", policy =>
                policy.Requirements.Add(new TenantRequirement()));

            // New policy - checks if authenticated user has access to tenant
            options.AddPolicy("RequireTenantAccess", policy =>
                policy.Requirements.Add(new TenantAccessRequirement()));
        });
    }

    public static WebApplication ConfigureTenantMiddleware(this WebApplication app)
    {
        app.UseMiddleware<TenantMiddleware>();
        return app;
    }
}