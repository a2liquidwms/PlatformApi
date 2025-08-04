using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using PlatformApi.Models.BaseModels;

namespace PlatformApi.Models;

[Table("role_permissions")]
public class RolePermission : BaseObject
{
    public Guid Id { get; set; } = Guid.NewGuid();
    
    [StringLength(50)]
    [ForeignKey(nameof(Permission))]
    public required string PermissionCode { get; set; }
    
    public required Guid RoleId { get; set; }
    
    public Role Role { get; set; } = null!;
    
    public Permission Permission { get; set; } = null!;
    
}