namespace PlatformApi.Models;

public class AuthTokenBundle
{
    public string? AccessToken { get; set; }
    public string? TokenType { get; set; }
    
    public int Expires { get; set; }
    
    public Guid? TenantId { get; set; }
    public Guid? SiteId { get; set; }
    public string? TenantSubdomain { get; set; }
}

public class AuthTokenBundleWithRefresh : AuthTokenBundle
{
    public string? RefreshToken { get; set; }
} 