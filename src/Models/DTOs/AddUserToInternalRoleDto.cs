using System.ComponentModel.DataAnnotations;

namespace PlatformApi.Models.DTOs;

public class AddUserToInternalRoleDto
{
    [Required]
    [EmailAddress]
    public required string Email { get; set; }
    
    [Required]
    public required string RoleId { get; set; }
}