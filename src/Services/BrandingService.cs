using PlatformApi.Models;

namespace PlatformApi.Services;

public interface IBrandingService
{
    Task<BrandingContext> GetBrandingContextAsync(string? subdomain = null, Guid? tenantId = null);
    Task<BrandingContext> GetDefaultBrandingContextAsync();
}

public class BrandingService : IBrandingService
{
    private readonly ITenantService _tenantService;
    private readonly IConfiguration _configuration;
    private readonly ILogger<BrandingService> _logger;
    private readonly string _baseDomain;

    public BrandingService(
        ITenantService tenantService, 
        IConfiguration configuration,
        ILogger<BrandingService> logger)
    {
        _tenantService = tenantService;
        _configuration = configuration;
        _logger = logger;
        _baseDomain = _configuration["AUTH_EMAIL_LINK_DOMAIN"] ?? throw new InvalidOperationException("AUTH_BASE_DOMAIN is required");
    }

    public async Task<BrandingContext> GetBrandingContextAsync(string? subdomain = null, Guid? tenantId = null)
    {
        TenantConfig? tenantConfig = null;

        try
        {
            // Try to get tenant config by subdomain first, then by tenantId
            if (!string.IsNullOrEmpty(subdomain))
            {
                tenantConfig = await _tenantService.GetTenantConfigBySubdomain(subdomain);
            }
            else if (tenantId.HasValue)
            {
                tenantConfig = await _tenantService.GetTenantConfigById(tenantId.Value);
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to get tenant config for subdomain: {Subdomain}, tenantId: {TenantId}", 
                subdomain, tenantId);
        }

        if (tenantConfig?.Tenant != null)
        {
            _logger.LogInformation("Tenant branding selected for {SiteName} (subdomain: {SubDomain}, tenantId: {TenantId})", 
                tenantConfig.Tenant.Name, tenantConfig.Tenant.SubDomain, tenantConfig.TenantId);
            
            return new BrandingContext
            {
                SiteName = tenantConfig.Tenant.Name,
                LogoPath = tenantConfig.LogoPath,
                PrimaryColor = tenantConfig.PrimaryColor ?? "#007bff",
                SubDomain = tenantConfig.Tenant.SubDomain,
                TenantId = tenantConfig.TenantId,
                BaseUrl = GetBaseUrl(tenantConfig.Tenant.SubDomain),
                EmailFromName = tenantConfig.Tenant.Name
            };
        }

        _logger.LogInformation("Falling back to default branding (subdomain: {Subdomain}, tenantId: {TenantId})", 
            subdomain, tenantId);
            
        return await GetDefaultBrandingContextAsync();
    }

    public async Task<BrandingContext> GetDefaultBrandingContextAsync()
    {
        return await Task.FromResult(new BrandingContext
        {
            SiteName = "Platform",
            LogoPath = "",
            PrimaryColor = "#1d86f8",
            SubDomain = null, 
            TenantId = null,
            BaseUrl = GetBaseUrl(null),
            EmailFromName = _configuration["DEFAULT_SITE_NAME"] ?? "Platform Auth"
        });
    }

    private string GetBaseUrl(string? subdomain)
    {
        var environment = _configuration["ASPNETCORE_ENVIRONMENT"] ?? "Development";
        var isDevelopment = environment.Equals("Development", StringComparison.OrdinalIgnoreCase);

        if (isDevelopment)
        {
            _logger.LogDebug("Using development environment for Email Base URL");
            return subdomain != null ? $"http://{subdomain}.{_baseDomain}" : $"http://{_baseDomain}";
        }

        return subdomain != null ? $"https://{subdomain}.{_baseDomain}" : $"https://{_baseDomain}";
    }
}