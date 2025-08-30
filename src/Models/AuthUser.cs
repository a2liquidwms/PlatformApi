using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Identity;

namespace PlatformApi.Models;

public class AuthUser : IdentityUser<Guid>
{
    
    public ICollection<UserRoles> UserRoles { get; set; } = new List<UserRoles>();
    
    public ICollection<RefreshToken> RefreshTokens { get; set; } = new List<RefreshToken>();
}

