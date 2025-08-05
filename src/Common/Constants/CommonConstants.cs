namespace PlatformApi.Common.Constants;

public static class CommonConstants
{
    public const string TenantHeaderKey = "X-Tenant-Id";
    
    public const string TenantHttpContext = "TenantId";
    
    public const string TenantsClaim = "tenants";
    
    public const string ActiveTenantClaim = "active_tenant";
    
    public const string ActiveSiteClaim = "active_site";
    
    public const string ClaimUserId = "userid";
    
    public const string RolesClaim = "roles";
    
    public const string AdminRolesClaim = "admin_roles";
    
    public const string PermissionRoleCacheKey = "PermissionRoleCacheKey";
}