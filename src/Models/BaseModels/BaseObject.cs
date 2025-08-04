using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace PlatformApi.Models.BaseModels;

public interface IBaseObject
{
    DateTime CreateDate { get; set; }
    string? CreatedBy { get; set; }
    DateTime? LastModifiedDate { get; set; }
    string? LastModifiedBy { get; set; }
    string? ModifiedSource { get; set; }
}

public class BaseObject : IBaseObject
{
    [Column("create_date")]
    public DateTime CreateDate { get; set; }

    [StringLength(100)]
    [Column("create_by")]
    public string? CreatedBy { get; set; }

    [Column("last_mod_date")]
    public DateTime? LastModifiedDate { get; set; }

    [MaxLength(100)]
    [Column("last_mod_by")]
    public string? LastModifiedBy { get; set; }

    [MaxLength(25)]
    [Column("modify_source")]
    public string? ModifiedSource { get; set; }
}

public class BaseObjectDto
{
    public DateTime CreateDate { get; private set; }
    [StringLength(30)]
    public string? CreatedBy { get; private set; }
    public DateTime? LastModifiedDate { get; private set; }
    [MaxLength(30)]
    public string? LastModifiedBy { get; private set; }
    [MaxLength(15)]
    public string? ModifiedSource { get; private set; }
}