using System.ComponentModel.DataAnnotations;

namespace PlatformApi.Models.DTOs;

public class AddUserToTenantDto
{
    [Required]
    [EmailAddress]
    public required string Email { get; set; }

    [Required]
    public required Guid TenantId { get; set; }
    
    public string? RoleId { get; set; }
}