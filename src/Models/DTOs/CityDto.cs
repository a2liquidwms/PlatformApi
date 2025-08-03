using System.ComponentModel.DataAnnotations;
using NetStarterCommon.Core.Common.Models.BaseModels;

namespace PlatformApi.Models.DTOs;

public class CityDto : BaseObjectDto
{
    public Guid? Id { get; set; }
    
    [StringLength(100)]
    public required string Name { get; set; }
    
    [StringLength(2)]
    public required string State { get; set; }
}