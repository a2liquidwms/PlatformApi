using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace PlatformApi.Models;

[Table("tenant_configs")]
public class TenantConfig
{
    public Guid Id { get; set; }

    public required Guid TenantId { get; set; }

    public virtual Tenant? Tenant { get; set; }

    [StringLength(50)]
    public string? SiteName { get; set; }
    
    public string? LogoPath { get; set; }

    [StringLength(15)]
    public string? PrimaryColor { get; set; }
    
    public decimal? GeocenterLat { get; set; }
    
    public decimal? GeocenterLong { get; set; }
    
}