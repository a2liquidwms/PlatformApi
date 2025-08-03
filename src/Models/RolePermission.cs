using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using NetStarterCommon.Core.Common.Models.BaseModels;

namespace PlatformApi.Models;

[Table("role_permission")]
public class RolePermission : BaseObject
{
    public Guid Id { get; set; }
    
    [StringLength(36)]
    public required string UserRoleId { get; set; }
    
    [Column(Order= 2)]
    [StringLength(36)]
    [ForeignKey(nameof(Permission))]
    public required string PermissionCode { get; set; }
    
    public AuthRole AuthRole { get; set; } = null!;
    
    public Permission Permission { get; set; } = null!;
    
}