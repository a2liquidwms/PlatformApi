using Microsoft.EntityFrameworkCore;
using NetStarterCommon.Core.Common.Constants;
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

    public TenantService(ILogger<TenantService> logger, PlatformDbContext context, IUnitOfWork<PlatformDbContext> uow, ISnsService snsService)
    {
        _logger = logger;
        _context = context;
        _uow = uow;
        _snsService = snsService;
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
        
        return obj;
    }

    public async Task<bool> Update(Guid id, Tenant obj)
    {
        if (id != obj.Id)
        {
            _logger.LogInformation("Invalid Id: {Id}", id);
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
        return true;
    }

    public async Task<bool> Delete(Guid id)
    {
        var obj = await GetById(id);
        if (obj == null)
        {
            _logger.LogInformation("Not Found, Id: {Id}", id);
            throw new NotFoundException();
        }
        _context.Tenants.Remove(obj);
        await _uow.CompleteAsync();
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
}