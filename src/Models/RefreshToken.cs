using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using NetStarterCommon.Core.Common.Models.BaseModels;

namespace PlatformApi.Models;

public class RefreshToken : BaseObject
{
    public Guid Id { get; set; }
    public required string Token { get; set; }
    [StringLength(36)]
    public required string UserId { get; set; }
    
    [ForeignKey(nameof(UserId))]
    public virtual AuthUser? User { get; set; }
    public DateTime Expires { get; set; }
    public bool IsRevoked { get; set; } = false;
    
    public Guid? TenantId { get; set; }
    
    public virtual Tenant? Tenant { get; set; }
}

public class RefreshRequest
{
    public required string UserId { get; set; }
    public required string RefreshToken { get; set; }
}