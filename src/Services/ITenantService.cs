using PlatformApi.Models;

namespace PlatformApi.Services;

public interface ITenantService
{
    Task<IEnumerable<Tenant>> GetAll();
    Task<Tenant?> GetById(Guid id);
    Task<Tenant> Add(Tenant obj);
    Task<bool> Update(Guid id, Tenant obj);
    Task<bool> Delete(Guid id);
    
    Task<TenantConfig?> GetTenantConfigById(Guid tenantId);
    Task<TenantConfig?> GetTenantConfigBySubdomain(string subdomain);
    Task<bool> UpdateTenantConfig(Guid tenantId, TenantConfig obj);
    
    // Tenant access methods
    Task<bool> HasTenantAccess(Guid userId, Guid tenantId);
}