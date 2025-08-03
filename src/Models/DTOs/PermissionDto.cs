using System.ComponentModel.DataAnnotations;
using PlatformApi.Models.BaseModels;

namespace PlatformApi.Models.DTOs;

public class PermissionDto : BaseObjectDto
{
    [StringLength(36)]
    public required string Code { get; set; }

    [StringLength(50)]
    public string? Description { get; set; }

    public bool IsDefaultFlg { get; set; }
    
}