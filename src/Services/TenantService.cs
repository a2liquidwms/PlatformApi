using Microsoft.EntityFrameworkCore;
using PlatformApi.Common.Constants;
using PlatformApi.Common.Services;
using PlatformApi.Data;
using PlatformApi.Models;
using PlatformApi.Models.Messages;

namespace PlatformApi.Services;

public class TenantService : ITenantService
{
    private readonly ILogger<TenantService> _logger;
    private readonly PlatformDbContext _context;
    private readonly IUnitOfWork<PlatformDbContext> _uow;
    private readonly ISnsService _snsService;
    private readonly ICacheService _cacheService;

    public TenantService(
        ILogger<TenantService> logger, 
        PlatformDbContext context, 
        IUnitOfWork<PlatformDbContext> uow, 
        ISnsService snsService,
        ICacheService cacheService)
    {
        _logger = logger;
        _context = context;
        _uow = uow;
        _snsService = snsService;
        _cacheService = cacheService;
    }

    public async Task<IEnumerable<Tenant>> GetAll()
    {
        return await _context.Tenants.AsNoTracking().ToListAsync();
    }

    public async Task<Tenant?> GetById(Guid id)
    {
        return await _context.Tenants.AsNoTracking().FirstOrDefaultAsync(r => r.Id == id);
    }

    public async Task<Tenant> Add(Tenant obj)
    {
        obj.SubDomain = obj.SubDomain.ToLower();
        _context.Tenants.Add(obj);
        await _uow.CompleteAsync();
        
        // Publish tenant-created message
        var tenantCreatedMessage = new TenantCreatedMessage
        {
            TenantId = obj.Id.ToString(),
            Code = obj.Code,
            Name = obj.Name
        };
        await _snsService.PublishTenantCreatedAsync(tenantCreatedMessage);
        
        // Invalidate all user tenant caches since a new tenant was added
        await _cacheService.InvalidateAllCachedUserTenantsAsync();
        
        return obj;
    }

    public async Task<bool> Update(Guid id, Tenant obj)
    {
        if (id != obj.Id)
        {
            _logger.LogWarning("Invalid ID mismatch for tenant update: provided {ProvidedId}, object {ObjectId}", id, obj.Id);
            throw new InvalidDataException(ErrorMessages.KeyNotMatch);
        }
        
        var mod = await GetById(id);

        if (mod == null)
        {
            throw new NotFoundException();
        }
        obj.SubDomain = obj.SubDomain.ToLower();

        _context.Tenants.Update(obj);
        await _uow.CompleteAsync();
        
        // Invalidate all user tenant caches since tenant was updated
        await _cacheService.InvalidateAllCachedUserTenantsAsync();
        
        return true;
    }

    public async Task<bool> Delete(Guid id)
    {
        var obj = await GetById(id);
        if (obj == null)
        {
            throw new NotFoundException();
        }
        _context.Tenants.Remove(obj);
        await _uow.CompleteAsync();
        
        // Invalidate all user tenant caches since tenant was deleted
        await _cacheService.InvalidateAllCachedUserTenantsAsync();
        
        return true;
    }
    
    public async Task<TenantConfig?> GetTenantConfigById(Guid tenantId)
    {
        return await _context.TenantConfigs
            .AsNoTracking()
            .Include(tc => tc.Tenant)
            .FirstOrDefaultAsync(tc => tc.TenantId == tenantId);
    }
    
    public async Task<TenantConfig?> GetTenantConfigBySubdomain(string subdomain)
    {
        if (string.IsNullOrEmpty(subdomain))
        {
            throw new ArgumentException("Subdomain cannot be null or empty", nameof(subdomain));
        }

        subdomain = subdomain.ToLower(); // Normalize subdomain to lowercase for consistent comparison
    
        // Join TenantConfigs with Tenants to find the config by subdomain
        return await _context.TenantConfigs
            .AsNoTracking()
            .Include(tc => tc.Tenant)
            .FirstOrDefaultAsync(tc => tc.Tenant != null && tc.Tenant.SubDomain.ToLower() == subdomain);
    }
    
    public async Task<bool> UpdateTenantConfig(Guid tenantId, TenantConfig obj)
    {
        var existingTenant = await GetById(tenantId);
        if (existingTenant == null)
        {
            throw new NotFoundException();
        }
        
        _context.TenantConfigs.Update(obj);
        await _uow.CompleteAsync();
        return true;
    }

    public async Task<Site?> GetSiteById(Guid id)
    {
        return await _context.Sites
            .AsNoTracking()
            .Include(s => s.Tenant)
            .FirstOrDefaultAsync(s => s.Id == id);
    }

    public async Task<Site?> GetSiteConfigById(Guid id, Guid tenantId)
    {
        var site = await GetSiteById(id);
        
        if (site == null)
        {
            return null;
        }
        
        if (site.TenantId != tenantId)
        {
            throw new InvalidDataException("Site does not belong to the specified tenant");
        }
        
        return site;
    }

    public async Task<Site> AddSite(Site site)
    {
        var existingTenant = await GetById(site.TenantId);
        if (existingTenant == null)
        {
            throw new InvalidDataException("Tenant not found");
        }

        _context.Sites.Add(site);
        await _uow.CompleteAsync();
        return site;
    }

    public async Task<bool> UpdateSite(Guid id, Site site)
    {
        if (id != site.Id)
        {
            _logger.LogWarning("Invalid site ID mismatch for site update: provided {ProvidedId}, object {ObjectId}", id, site.Id);
            throw new InvalidDataException(ErrorMessages.KeyNotMatch);
        }

        var existingSite = await GetSiteById(id);
        if (existingSite == null)
        {
            throw new NotFoundException();
        }

        var existingTenant = await GetById(site.TenantId);
        if (existingTenant == null)
        {
            throw new InvalidDataException("Tenant not found");
        }

        _context.Sites.Update(site);
        await _uow.CompleteAsync();
        return true;
    }

    public async Task<bool> DeleteSite(Guid id)
    {
        var site = await GetSiteById(id);
        if (site == null)
        {
            throw new NotFoundException();
        }

        _context.Sites.Remove(site);
        await _uow.CompleteAsync();
        return true;
    }

    public async Task<IEnumerable<Site>> GetSitesByTenantId(Guid tenantId)
    {
        return await _context.Sites
            .AsNoTracking()
            .Where(s => s.TenantId == tenantId)
            .ToListAsync();
    }


}