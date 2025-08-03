using System.ComponentModel;

namespace PlatformApi.Models;

[Flags]
public enum RoleScope
{
    [Description("Internal system roles for super admins and support")]
    Internal = 1,
    
    [Description("Tenant-wide roles for tenant admins and cross-site users")]
    Tenant = 2,
    
    [Description("Site-specific roles for individual site users")]
    Site = 4
}