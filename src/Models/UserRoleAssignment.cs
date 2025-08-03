using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using NetStarterCommon.Core.Common.Models.BaseModels;

namespace PlatformApi.Models;

[Table("user_role_assignment")]
public class UserRoleAssignment : BaseObject
{
    public Guid Id { get; set; } = Guid.NewGuid();
    
    [Required]
    [StringLength(36)]
    public required string UserId { get; set; }
    
    [Required]
    [StringLength(36)]
    public required string RoleId { get; set; }
    
    public Guid? TenantId { get; set; }
    
    public Guid? SiteId { get; set; }
    
    public RoleScope Scope { get; set; }
    
    public bool IsActive { get; set; } = true;
    
    public virtual AuthUser? User { get; set; }
    
    public virtual AuthRole? Role { get; set; }
    
    public virtual Tenant? Tenant { get; set; }
    
    public virtual Site? Site { get; set; }
}