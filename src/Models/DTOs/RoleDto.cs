using System.ComponentModel.DataAnnotations;

namespace PlatformApi.Models.DTOs;

public class RoleDto
{
    public string? Id { get; set; }

    [StringLength(20)]
    public required string Name { get; set; }
    
    [StringLength(50)]
    public string? Description { get; set; }
    
    public bool IsAdmin { get; set; } = false;
    
    public ICollection<PermissionDto>? Permissions { get;  set; } = new List<PermissionDto>();
}