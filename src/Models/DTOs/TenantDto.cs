using System.ComponentModel.DataAnnotations;

namespace PlatformApi.Models.DTOs;

public class TenantDto
{
    public Guid? Id { get; set; }

    [StringLength(25)]
    public required string Code { get; set; }
    
    [StringLength(50)]
    public required string Name { get; set; }
    
    [StringLength(50)]
    public string? SubDomain { get; set; }
    
}