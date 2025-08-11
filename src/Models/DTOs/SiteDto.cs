using System.ComponentModel.DataAnnotations;

namespace PlatformApi.Models.DTOs;

public class SiteDto
{
    public Guid Id { get; set; }
    
    [Required]
    [StringLength(25)]
    public required string Code { get; set; }
    
    [Required]
    [StringLength(100)]
    public required string Name { get; set; }
    
    [Required]
    public required Guid TenantId { get; set; }
    
    public bool IsActive { get; set; } = true;
}