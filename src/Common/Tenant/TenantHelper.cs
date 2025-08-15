using PlatformApi.Common.Constants;

namespace PlatformApi.Common.Tenant;

public class TenantHelper
{
    private readonly IHttpContextAccessor _httpContextAccessor;
    private readonly ILogger<TenantHelper> _logger;

    public TenantHelper(IHttpContextAccessor httpContextAccessor, ILogger<TenantHelper> logger)
    {
        _httpContextAccessor = httpContextAccessor;
        _logger = logger;
    }

    public Guid GetTenantId()
    {
        var httpContext = _httpContextAccessor.HttpContext;
        
        if (httpContext?.User?.Identity?.IsAuthenticated == true)
        {
            var tenantIdClaim = httpContext.User.FindFirst(CommonConstants.ActiveTenantClaim);
            if (tenantIdClaim != null && !string.IsNullOrWhiteSpace(tenantIdClaim.Value))
            {
                if (Guid.TryParse(tenantIdClaim.Value, out var tenantId))
                {
                    return tenantId;
                }
                else
                {
                    _logger.LogWarning("Invalid Tenant ID format in JWT claim: {TenantId}", tenantIdClaim.Value);
                    throw new InvalidDataException("Invalid Tenant ID format in JWT claim");
                }
            }
        }

        return Guid.Empty;
    }

    public Guid GetSiteId()
    {
        var httpContext = _httpContextAccessor.HttpContext;
        
        if (httpContext?.User?.Identity?.IsAuthenticated == true)
        {
            var siteIdClaim = httpContext.User.FindFirst(CommonConstants.ActiveSiteClaim);
            if (siteIdClaim != null && !string.IsNullOrWhiteSpace(siteIdClaim.Value))
            {
                if (Guid.TryParse(siteIdClaim.Value, out var siteId))
                {
                    return siteId;
                }
                else
                {
                    _logger.LogWarning("Invalid Site ID format in JWT claim: {SiteId}", siteIdClaim.Value);
                    throw new InvalidDataException("Invalid Site ID format in JWT claim");
                }
            }
        }

        return Guid.Empty;
    }
}