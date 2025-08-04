using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using Microsoft.EntityFrameworkCore;
using PlatformApi.Models.BaseModels;

namespace PlatformApi.Models;

[Table("user_site")]
[Index(nameof(TenantId), Name = "IX_user_site_tenant_id")]
[Index(nameof(SiteId), Name = "IX_user_site_site_id")]
[Index(nameof(UserId), Name = "IX_user_site_user_id")]
public class UserSite : BaseObject
{
    [Required]
    public required Guid UserId { get; set; }
    
    [Required]
    public required Guid SiteId { get; set; }
    
    [Required]
    public required Guid TenantId { get; set; }
    
    public bool IsActive { get; set; } = true;
    
    public virtual AuthUser? User { get; set; }
    
    public virtual Site? Site { get; set; }
    
    public virtual Tenant? Tenant { get; set; }
}