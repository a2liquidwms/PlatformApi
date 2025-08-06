using System.ComponentModel.DataAnnotations;
using PlatformApi.Models.BaseModels;

namespace PlatformApi.Models.DTOs;

public class RoleCreateDto : BaseObjectDto
{
    [StringLength(20)]
    public required string Name { get; set; }

    [StringLength(50)]
    public string? Description { get; set; }
    
    [StringLength(50)]
    public string? NormalizedName { get; set; }
    
    public required RoleScope Scope { get; set; }
    
    public Guid? TenantId { get; set; }
    
    public Guid? SiteId { get; set; }
    
    public bool IsSystemRole { get; set; } = false;
    
    public ICollection<PermissionDto>? Permissions { get; private set; } = new List<PermissionDto>();
}