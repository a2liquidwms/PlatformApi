using System.ComponentModel.DataAnnotations;
using NetStarterCommon.Core.Common.Models.BaseModels;

namespace PlatformApi.Models.DTOs;

public class TenantDto : BaseObjectDto
{
    public Guid? Id { get; set; }

    [StringLength(10)]
    public required string Code { get; set; }
    
    [StringLength(50)]
    public required string Name { get; set; }
    
    [StringLength(50)]
    public required string SubDomain { get; set; }
    
    [StringLength(2)]
    public string? State { get; set; }
    
    public string? MainAddress { get; set; }
    
    public List<CityDto>? Cities { get; set; }
}