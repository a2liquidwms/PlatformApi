using System.ComponentModel.DataAnnotations;

namespace PlatformApi.Models.DTOs;

public class SiteUserDto
{
    public required Guid UserId { get; set; }
    public required string Email { get; set; }
    public List<RoleDto>? Roles { get; set; }
}

public class SiteUserWithRolesDto
{
    public required Guid UserId { get; set; }
    public required string Email { get; set; }
    public required Guid SiteId { get; set; }
    public required List<RoleNoPermissionDto> Roles { get; set; } = new();
}

public class AddUserToSiteDto
{
    [Required]
    [EmailAddress]
    public required string Email { get; set; }
    
    [Required]
    public required Guid SiteId { get; set; }
    
    public Guid? RoleId { get; set; }
}