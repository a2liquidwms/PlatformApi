namespace PlatformApi.Models;

public class BrandingContext
{
    public string SiteName { get; set; } = string.Empty;
    public string? LogoPath { get; set; }
    public string PrimaryColor { get; set; } = "#007bff";
    public string? SubDomain { get; set; }
    public Guid? TenantId { get; set; }
    public string BaseUrl { get; set; } = string.Empty;
    public string EmailFromName { get; set; } = string.Empty;
}