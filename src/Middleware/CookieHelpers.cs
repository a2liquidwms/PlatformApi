using Microsoft.AspNetCore.Mvc;

namespace PlatformApi.Middleware;

public static class CookieHelpers
{
    private const string DefaultRefreshTokenCookieName = "PlatRefreshToken";
    
    private static string GetRefreshTokenCookieName(IConfiguration configuration)
    {
        return configuration["AUTH_COOKIE_NAME"] ?? DefaultRefreshTokenCookieName;
    }
    
    public static void SetRefreshTokenCookie(this ControllerBase controller, string refreshToken, IConfiguration configuration, IWebHostEnvironment environment, ILogger? logger = null)
    {
        var isSafari = IsSafariBrowser(controller.Request);
        
        var cookieOptions = new CookieOptions
        {
            HttpOnly = true,
            Secure = !environment.IsDevelopment(), // false for dev (HTTP), true for prod (HTTPS)
            SameSite = isSafari ? SameSiteMode.None : (environment.IsDevelopment() ? SameSiteMode.Lax : SameSiteMode.Strict),
            Expires = DateTime.UtcNow.AddDays(GetRefreshTokenExpiryDays(configuration)),
            Path = "/",
            Domain = GetCookieDomain(configuration)
        };
        
        logger?.LogInformation("Setting cookie for Safari: {IsSafari}, SameSite: {SameSite}, Secure: {Secure}, Domain: {Domain}", 
            isSafari, cookieOptions.SameSite, cookieOptions.Secure, cookieOptions.Domain);
        
        var cookieName = GetRefreshTokenCookieName(configuration);
        controller.Response.Cookies.Append(cookieName, refreshToken, cookieOptions);
    }
    
    public static string? GetRefreshTokenFromCookie(this ControllerBase controller, IConfiguration configuration)
    {
        var cookieName = GetRefreshTokenCookieName(configuration);
        return controller.Request.Cookies[cookieName];
    }
    
    public static void ClearRefreshTokenCookie(this ControllerBase controller, IConfiguration configuration, IWebHostEnvironment environment, ILogger? logger = null)
    {
        var isSafari = IsSafariBrowser(controller.Request);
        
        var cookieOptions = new CookieOptions
        {
            HttpOnly = true,
            Secure = false, // Use false for clearing to ensure it works in both dev and prod
            SameSite = isSafari ? SameSiteMode.None : SameSiteMode.Lax,
            Expires = DateTime.UtcNow.AddDays(-1), // Expire immediately
            Path = "/",
            Domain = GetCookieDomain(configuration)
        };
        
        var cookieName = GetRefreshTokenCookieName(configuration);
        controller.Response.Cookies.Append(cookieName, string.Empty, cookieOptions);
    }
    
    public static bool HasApiTestingHeader(this ControllerBase controller)
    {
        return controller.Request.Headers.ContainsKey("X-HTTP-API");
    }
    
    
    private static bool IsSafariBrowser(HttpRequest request)
    {
        var userAgent = request.Headers["User-Agent"].ToString();
        // Safari contains "Safari" but not "Chrome" (since Chrome also contains "Safari")
        return userAgent.Contains("Safari", StringComparison.OrdinalIgnoreCase) && 
               !userAgent.Contains("Chrome", StringComparison.OrdinalIgnoreCase);
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