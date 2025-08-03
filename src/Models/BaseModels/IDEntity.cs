using System.ComponentModel.DataAnnotations;

namespace PlatformApi.Models.BaseModels;

public interface IDEntity
{
    [Key]
    Guid Id { get; set; }
}