using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Identity;
using PlatformApi.Models.BaseModels;

namespace PlatformApi.Models;

public class AuthUser : IdentityUser<Guid>
{
    public ICollection<UserTenant> UserTenants { get; set; } = new List<UserTenant>();
    
    public ICollection<UserSite> UserSites { get; set; } = new List<UserSite>();
    
    public ICollection<UserRoles> UserRoles { get; set; } = new List<UserRoles>();
    
    public ICollection<RefreshToken> RefreshTokens { get; set; } = new List<RefreshToken>();
}

