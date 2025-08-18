using System.ComponentModel.DataAnnotations;

namespace PlatformApi.Models.DTOs;

public class AddUserToTenantRoleDto
{
    [Required]
    [EmailAddress]
    public required string Email { get; set; }

    [Required]
    public required Guid TenantId { get; set; }

    [Required]
    public required string RoleId { get; set; }
}