# Hierarchical Permission Assignment Examples

## Using `PermissionService.CanPermissionBeAssignedToRole()`

### Internal Role (Highest Level)
```csharp
// Internal roles can have ALL permission types
CanPermissionBeAssignedToRole(null, RoleScope.Internal);           // ✅ true - null permissions
CanPermissionBeAssignedToRole(RoleScope.Internal, RoleScope.Internal); // ✅ true
CanPermissionBeAssignedToRole(RoleScope.Tenant, RoleScope.Internal);   // ✅ true  
CanPermissionBeAssignedToRole(RoleScope.Site, RoleScope.Internal);     // ✅ true
CanPermissionBeAssignedToRole(RoleScope.Default, RoleScope.Internal);  // ✅ true
```

### Tenant Role
```csharp
// Tenant roles can have Tenant, Site, and Default permissions (but NOT Internal)
CanPermissionBeAssignedToRole(null, RoleScope.Tenant);             // ✅ true - null permissions
CanPermissionBeAssignedToRole(RoleScope.Internal, RoleScope.Tenant); // ❌ false - Internal > Tenant
CanPermissionBeAssignedToRole(RoleScope.Tenant, RoleScope.Tenant);   // ✅ true
CanPermissionBeAssignedToRole(RoleScope.Site, RoleScope.Tenant);     // ✅ true
CanPermissionBeAssignedToRole(RoleScope.Default, RoleScope.Tenant);  // ✅ true
```

### Site Role
```csharp
// Site roles can have Site and Default permissions (but NOT Internal or Tenant)
CanPermissionBeAssignedToRole(null, RoleScope.Site);               // ✅ true - null permissions
CanPermissionBeAssignedToRole(RoleScope.Internal, RoleScope.Site);  // ❌ false - Internal > Site
CanPermissionBeAssignedToRole(RoleScope.Tenant, RoleScope.Site);    // ❌ false - Tenant > Site
CanPermissionBeAssignedToRole(RoleScope.Site, RoleScope.Site);      // ✅ true
CanPermissionBeAssignedToRole(RoleScope.Default, RoleScope.Site);   // ✅ true
```

### Default Role (Lowest Level)
```csharp
// Default roles can ONLY have Default permissions
CanPermissionBeAssignedToRole(null, RoleScope.Default);             // ✅ true - null permissions
CanPermissionBeAssignedToRole(RoleScope.Internal, RoleScope.Default); // ❌ false
CanPermissionBeAssignedToRole(RoleScope.Tenant, RoleScope.Default);   // ❌ false
CanPermissionBeAssignedToRole(RoleScope.Site, RoleScope.Default);     // ❌ false
CanPermissionBeAssignedToRole(RoleScope.Default, RoleScope.Default);  // ✅ true
```

## Real-world Examples

### Adding permissions to a Tenant Admin role
```csharp
// These would all be valid for a Tenant role:
- "TENANT_MANAGE_USERS" (RoleScope.Tenant)     ✅
- "SITE_VIEW_ANALYTICS" (RoleScope.Site)       ✅  
- "DEFAULT_VIEW_PROFILE" (RoleScope.Default)   ✅
- "GLOBAL_PERMISSION" (null scope)             ✅

// This would be invalid:
- "INTERNAL_SYSTEM_CONFIG" (RoleScope.Internal) ❌
```

### Adding permissions to a Site Manager role
```csharp
// These would be valid for a Site role:
- "SITE_MANAGE_CONTENT" (RoleScope.Site)       ✅
- "DEFAULT_VIEW_PROFILE" (RoleScope.Default)   ✅
- "GLOBAL_PERMISSION" (null scope)             ✅

// These would be invalid:
- "INTERNAL_SYSTEM_CONFIG" (RoleScope.Internal) ❌
- "TENANT_MANAGE_BILLING" (RoleScope.Tenant)   ❌
```