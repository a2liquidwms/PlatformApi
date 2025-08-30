using Microsoft.AspNetCore.Mvc;

namespace PlatformApi.Middleware;

public static class CookieHelpers
{
    private const string RefreshTokenCookieName = "refreshToken";
    
    public static void SetRefreshTokenCookie(this ControllerBase controller, string refreshToken, IConfiguration configuration, IWebHostEnvironment environment)
    {
        var cookieOptions = new CookieOptions
        {
            HttpOnly = true,
            Secure = !environment.IsDevelopment(), // false for dev (HTTP), true for prod (HTTPS)
            SameSite = environment.IsDevelopment() ? SameSiteMode.Lax : SameSiteMode.Strict, // Lax for dev/Safari, Strict for prod
            Expires = DateTime.UtcNow.AddDays(GetRefreshTokenExpiryDays(configuration)),
            Path = "/",
            Domain = GetCookieDomain(configuration)
        };
        
        controller.Response.Cookies.Append(RefreshTokenCookieName, refreshToken, cookieOptions);
    }
    
    public static string? GetRefreshTokenFromCookie(this ControllerBase controller)
    {
        return controller.Request.Cookies[RefreshTokenCookieName];
    }
    
    public static void ClearRefreshTokenCookie(this ControllerBase controller, IConfiguration configuration)
    {
        var cookieOptions = new CookieOptions
        {
            HttpOnly = true,
            Secure = false, // Use false for clearing to ensure it works in both dev and prod
            SameSite = SameSiteMode.Lax,
            Expires = DateTime.UtcNow.AddDays(-1), // Expire immediately
            Path = "/",
            Domain = GetCookieDomain(configuration)
        };
        
        controller.Response.Cookies.Append(RefreshTokenCookieName, string.Empty, cookieOptions);
    }
    
    public static bool HasApiTestingHeader(this ControllerBase controller)
    {
        return controller.Request.Headers.ContainsKey("X-HTTP-API");
    }
    
    private static string? GetCookieDomain(IConfiguration configuration)
    {
        return configuration["AUTH_COOKIE_DOMAIN"];
    }
    
    private static int GetRefreshTokenExpiryDays(IConfiguration configuration)
    {
        if (int.TryParse(configuration["AUTH_REFRESH_TOKEN_DAYS"], out var days))
        {
            return days;
        }
        return 180; // Default 180 days as per env example
    }
}