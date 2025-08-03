using System.ComponentModel.DataAnnotations;

namespace PlatformApi.Models.DTOs;

public class AddUserToRoleDto
{
    [Required]
    [EmailAddress]
    public required string Email { get; set; }

    public Guid? TenantId { get; set; }

    public Guid? SiteId { get; set; }

    [Required]
    public required string RoleId { get; set; }
    
    public RoleScope Scope { get; set; }
}