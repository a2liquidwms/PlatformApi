using System.ComponentModel.DataAnnotations;

namespace PlatformApi.Common.Models.BaseModels;

public interface IDEntity
{
    [Key]
    Guid Id { get; set; }
}