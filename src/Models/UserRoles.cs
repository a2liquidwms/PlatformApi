using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using PlatformApi.Models.BaseModels;

namespace PlatformApi.Models;

[Table("user_roles")]
public class UserRoles : BaseObject
{
    public Guid Id { get; set; } = Guid.NewGuid();
    
    [Required]
    public required Guid UserId { get; set; }
    
    [Required]
    public required Guid RoleId { get; set; }
    
    public Guid? TenantId { get; set; }
    
    public Guid? SiteId { get; set; }
    
    public RoleScope Scope { get; set; }
    
    public virtual AuthUser? User { get; set; }
    
    public virtual Role? Role { get; set; }
    
    public virtual Tenant? Tenant { get; set; }
    
    public virtual Site? Site { get; set; }
}