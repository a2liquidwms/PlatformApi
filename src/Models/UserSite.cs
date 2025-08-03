using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using NetStarterCommon.Core.Common.Models.BaseModels;

namespace PlatformApi.Models;

[Table("user_site")]
public class UserSite : BaseObject
{
    [Required]
    [StringLength(36)]
    public required string UserId { get; set; }
    
    [Required]
    public required Guid SiteId { get; set; }
    
    [Required]
    public required Guid TenantId { get; set; }
    
    public bool IsActive { get; set; } = true;
    
    public virtual AuthUser? User { get; set; }
    
    public virtual Site? Site { get; set; }
    
    public virtual Tenant? Tenant { get; set; }
}