using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using PlatformApi.Common.Models.BaseModels;

namespace PlatformApi.Models;

[Table("permissions")]
public class Permission : BaseObject
{
    [Key]
    [StringLength(50)]
    public required string Code { get; set; }

    [StringLength(50)]
    public string? Description { get; set; }
    
    public RoleScope? RoleScope { get; set; }
    
    public virtual ICollection<RolePermission>? RolePermissions { get; set; }
}