using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using PlatformApi.Models.BaseModels;

namespace PlatformApi.Models;

[Table("user_refresh_tokens")]
public class RefreshToken : BaseObject
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public required string Token { get; set; }
    public required Guid UserId { get; set; }
    
    [ForeignKey(nameof(UserId))]
    public virtual AuthUser? User { get; set; }
    public DateTime Expires { get; set; }
    public bool IsRevoked { get; set; } = false;
    
    public Guid? TenantId { get; set; }
    public Guid? SiteId { get; set; }
    
    public virtual Tenant? Tenant { get; set; }
    public virtual Site? Site { get; set; }
}

public class RefreshRequest
{
    public Guid? UserId { get; set; } // Optional - will be derived from refresh token in cookie
    public string? RefreshToken { get; set; } // Optional - will come from cookie
}