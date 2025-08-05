using Microsoft.AspNetCore.Authorization;

namespace PlatformApi.Common.Permissions;

public static class PermissionStartupExtensions
{

    public static void PermissionCheckServices(this IServiceCollection services, IConfiguration configuration)
    {
        services.AddSingleton<IAuthorizationPolicyProvider, PermissionAuthPolicy>();
        services.AddSingleton<IAuthorizationHandler, PermissionHandler>();
        services.AddMemoryCache();
    }

    public static WebApplication ConfigurePermissions(this WebApplication app)
    {
        app.UseMiddleware<PermissionsMiddleware>();   //useTenant = true
        app.UseAuthorization();
        return app;
    }
    
}