using System.ComponentModel.DataAnnotations;

namespace NetStarterCommon.Core.Common.Models.BaseModels;

public interface IDEntity
{
    [Key]
    Guid Id { get; set; }
}