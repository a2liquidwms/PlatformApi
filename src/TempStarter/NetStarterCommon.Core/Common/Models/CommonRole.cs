using System.Collections.ObjectModel;

namespace NetStarterCommon.Core.Common.Models;

public class CommonRole
{
    public Guid Id { get; set; }
    
    public string? Code { get; set; }
    
    public Collection<CommonPermission>? Permissions { get; set; }
    

}