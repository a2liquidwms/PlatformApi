namespace PlatformApi.Common.Constants;

public static class CommonConstants
{
    public const string TenantHeaderKey = "X-Tenant-Id";
    
    public const string TenantHeaderSubdomain = "X-Tenant-Subdomain";
    
    public const string SiteHeaderKey = "X-Site-Id";
    
    public const string TenantHttpContext = "TenantId";
    public const string SiteHttpContext = "SiteId";
    
    public const string ActiveTenantClaim = "active_tenant";
    
    public const string ActiveSiteClaim = "active_site";
    
    public const string ClaimUserId = "userid";
    
    public const string RolesClaim = "roles";
    
    public const string TenantCountClaim = "tenant_count";
    
    public const string SiteCountClaim = "site_count";
    
    public const string PermissionRoleCacheKey = "PermissionRoleCacheKey";
}