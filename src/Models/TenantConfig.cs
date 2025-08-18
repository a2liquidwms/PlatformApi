using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace PlatformApi.Models;

[Table("tenant_configs")]
public class TenantConfig
{
    public Guid Id { get; set; } = Guid.NewGuid();

    public required Guid TenantId { get; set; }

    public virtual Tenant? Tenant { get; set; }
    
    public string? LogoPath { get; set; }

    [StringLength(15)]
    public string? PrimaryColor { get; set; }
    
}