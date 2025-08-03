using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using Microsoft.EntityFrameworkCore;
using PlatformApi.Models.BaseModels;

namespace PlatformApi.Models;

[Table("tenants")]
[Index(nameof(Code), IsUnique = true)]
[Index(nameof(Name), IsUnique = true)]
[Index(nameof(SubDomain), IsUnique = true)]
public class Tenant : BaseObject
{
    [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
    public Guid Id { get; set; }
    
    [StringLength(10)]
    public required string Code { get; set; }
    
    [StringLength(30)]
    public required string Name { get; set; }
    
    [StringLength(50)] 
    public required string SubDomain { get; set; }
    
    public TenantConfig? TenantConfig { get; set; }
    
    public virtual ICollection<UserTenant>? UserTenants { get; set; }
    
    public virtual ICollection<Site>? Sites { get; set; }
}
