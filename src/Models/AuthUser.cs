using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Identity;
using PlatformApi.Models.BaseModels;

namespace PlatformApi.Models;

public class AuthUser : IdentityUser
{
    public ICollection<UserTenant> UserTenants { get; set; } = new List<UserTenant>();
    
    public ICollection<UserSite> UserSites { get; set; } = new List<UserSite>();
    
    public ICollection<UserRoles> UserRoles { get; set; } = new List<UserRoles>();
    
    public ICollection<RefreshToken> RefreshTokens { get; set; } = new List<RefreshToken>();
}

public class AuthRole : IdentityRole, IBaseObject
{
    [StringLength(50)]
    public string? Description { get; set; }
    
    public RoleScope Scope { get; set; } = RoleScope.Tenant;
    
    public int HierarchyLevel { get; set; } = 2;
    
    public Guid? TenantId { get; set; }
    
    public Guid? SiteId { get; set; }
    
    public bool IsSystemRole { get; set; } = false;

    public ICollection<UserRoles>? UserRoles { get; set; } = new List<UserRoles>();
    
    public ICollection<RolePermission>? RolePermissions { get; set; } = new List<RolePermission>();

    public DateTime CreateDate { get; set; }
    
    [StringLength(100)]
    public string? CreatedBy { get; set; }
    public DateTime? LastModifiedDate { get; set; }
    [StringLength(100)]
    public string? LastModifiedBy { get; set; }
    
    [StringLength(30)]
    public string? ModifiedSource { get; set; }
}