using System.ComponentModel;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using PlatformApi.Models.BaseModels;

namespace PlatformApi.Models;

[Table("permissions")]
public class Permission : BaseObject
{
    [Key]
    [StringLength(36)]
    public required string Code { get; set; }

    [StringLength(50)]
    public string? Description { get; set; }
    
    [DefaultValue(false)]
    public bool IsDefaultFlg { get; set; } = false;
    
    public RoleScope ApplicableScopes { get; set; } = RoleScope.Internal | RoleScope.Tenant | RoleScope.Site;
    
    public virtual ICollection<RolePermission>? RolePermissions { get; set; }
}