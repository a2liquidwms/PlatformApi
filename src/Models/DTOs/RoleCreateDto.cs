using System.ComponentModel.DataAnnotations;
using NetStarterCommon.Core.Common.Models.BaseModels;

namespace PlatformApi.Models.DTOs;

public class RoleCreateDto : BaseObjectDto
{
    [StringLength(20)]
    public required string Name { get; set; }

    [StringLength(50)]
    public string? Description { get; set; }
    
    [StringLength(50)]
    public string? NormalizedName { get; set; }
    
    public ICollection<PermissionDto>? Permissions { get; private set; } = new List<PermissionDto>();
}