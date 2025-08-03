using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Identity;
using NetStarterCommon.Core.Common.Models.BaseModels;

namespace PlatformApi.Models;

public class AuthUser : IdentityUser
{
    public ICollection<UserTenant> UserTenants { get; set; } = new List<UserTenant>();
    
    public ICollection<RefreshToken> RefreshTokens { get; set; } = new List<RefreshToken>();
}

public class AuthRole : IdentityRole, IBaseObject
{
    [StringLength(50)]
    public string? Description { get; set; }

    public bool IsAdmin { get; set; } = false;

    public ICollection<UserTenantRole>? UserTenantRoles { get; set; } = new List<UserTenantRole>();
    
    public ICollection<RolePermission>? RolePermissions { get; set; } = new List<RolePermission>();

    public DateTime CreateDate { get; set; }
    public string? CreatedBy { get; set; }
    public DateTime? LastModifiedDate { get; set; }
    public string? LastModifiedBy { get; set; }
    public string? ModifiedSource { get; set; }
}