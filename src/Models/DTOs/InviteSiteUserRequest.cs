using System.ComponentModel.DataAnnotations;

namespace PlatformApi.Models.DTOs;

public class InviteSiteUserRequest
{
    [Required]
    [EmailAddress]
    public required string Email { get; set; }

    [Required]
    public required Guid SiteId { get; set; }

    [Required]
    public required string RoleId { get; set; }
}