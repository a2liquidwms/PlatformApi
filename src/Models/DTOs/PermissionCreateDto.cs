using System.ComponentModel.DataAnnotations;

namespace PlatformApi.Models.DTOs;

public class PermissionCreateDto
{
    [StringLength(36)]
    public required string Code { get; set; }

    [StringLength(50)]
    public string? Description { get; set; }
    
    public RoleScope? RoleScope { get; set; }
}