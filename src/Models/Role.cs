using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using Microsoft.EntityFrameworkCore;
using PlatformApi.Common.Models.BaseModels;

namespace PlatformApi.Models;

[Table("roles")]
[Index(nameof(TenantId))]
[Index(nameof(Scope))]
[Index(nameof(TenantId), nameof(Scope))]
[Index(nameof(SiteId))]
public class Role : BaseObject
{
    public Guid Id { get; set; } = Guid.NewGuid();
    
    [Required]
    [StringLength(256)]
    public required string Name { get; set; }
    
    [StringLength(50)]
    public string? Description { get; set; }
    
    public required RoleScope Scope { get; set; }
    
    public Guid? TenantId { get; set; }
    
    public Guid? SiteId { get; set; }
    
    public bool IsSystemRole { get; set; } = false;

    public virtual ICollection<UserRoles>? UserRoles { get; set; } = new List<UserRoles>();
    
    public virtual ICollection<RolePermission>? RolePermissions { get; set; } = new List<RolePermission>();
}