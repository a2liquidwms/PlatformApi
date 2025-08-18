using Microsoft.Extensions.Caching.Memory;
using PlatformApi.Models.DTOs;

namespace PlatformApi.Common.Services;

public class MemoryCacheService : ICacheService
{
    private readonly IMemoryCache _memoryCache;
    private readonly ILogger<MemoryCacheService> _logger;

    // Domain-specific cache methods for User Tenants
    private const string UserTenantGenerationKey = "user_tenant_cache_generation";
    private const int UserTenantCacheMinutes = 5;

    // Domain-specific cache methods for User Sites  
    private const string UserSiteGenerationKey = "user_site_cache_generation";
    private const int UserSiteCacheMinutes = 5;
    
    public MemoryCacheService(IMemoryCache memoryCache, ILogger<MemoryCacheService> logger)
    {
        _memoryCache = memoryCache;
        _logger = logger;
    }

    public Task<T?> GetAsync<T>(string key)
    {
        try
        {
            _memoryCache.TryGetValue(key, out var value);
            if (value is T typedValue)
                return Task.FromResult<T?>(typedValue);
            return Task.FromResult<T?>(default(T));
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error getting cache key {Key}", key);
            return Task.FromResult(default(T));
        }
    }

    public Task SetAsync<T>(string key, T value, TimeSpan? expiration = null, TimeSpan? slidingExpiration = null)
    {
        try
        {
            var options = new MemoryCacheEntryOptions();

            if (expiration.HasValue)
            {
                options.SetAbsoluteExpiration(expiration.Value);
            }

            if (slidingExpiration.HasValue)
            {
                options.SetSlidingExpiration(slidingExpiration.Value);
            }

            _memoryCache.Set(key, value, options);
            return Task.CompletedTask;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error setting cache key {Key}", key);
            return Task.CompletedTask;
        }
    }

    public Task RemoveAsync(string key)
    {
        try
        {
            _memoryCache.Remove(key);
            return Task.CompletedTask;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error removing cache key {Key}", key);
            return Task.CompletedTask;
        }
    }

    public Task RemoveByPatternAsync(string pattern)
    {
        try
        {
            // Memory cache doesn't support pattern removal directly
            // This is a limitation we'll handle using generation-based invalidation
            // in the calling code, similar to current UserService approach
            _logger.LogWarning("Pattern-based removal not directly supported in memory cache for pattern: {Pattern}", pattern);
            return Task.CompletedTask;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error removing cache pattern {Pattern}", pattern);
            return Task.CompletedTask;
        }
    }

    public Task<bool> ExistsAsync(string key)
    {
        try
        {
            var exists = _memoryCache.TryGetValue(key, out _);
            return Task.FromResult(exists);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error checking cache key existence {Key}", key);
            return Task.FromResult(false);
        }
    }

    public Task<(bool Success, T? Value)> TryGetAsync<T>(string key)
    {
        try
        {
            var success = _memoryCache.TryGetValue(key, out var value);
            if (success && value is T typedValue)
                return Task.FromResult((true, (T?)typedValue));
            return Task.FromResult((false, default(T?)));
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error trying to get cache key {Key}", key);
            return Task.FromResult((false, default(T?)));
        }
    }

    public async Task<T?> GetWithGenerationAsync<T>(string key, string generationKey)
    {
        try
        {
            var userGenerationKey = $"{key}_generation";
            
            // Get the cached value, user generation, and current generation
            var (valueExists, cachedValue) = await TryGetAsync<T>(key);
            var (userGenExists, userGeneration) = await TryGetAsync<int>(userGenerationKey);
            var (currentGenExists, currentGeneration) = await TryGetAsync<int>(generationKey);

            // If no current generation exists, initialize it
            if (!currentGenExists)
            {
                currentGeneration = 1;
                await SetAsync(generationKey, currentGeneration);
            }

            // Check if cache is valid (exists and generations match)
            if (valueExists && userGenExists && userGeneration == currentGeneration)
            {
                return cachedValue;
            }

            return default(T);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error getting cache with generation for key {Key}", key);
            return default(T);
        }
    }

    public async Task SetWithGenerationAsync<T>(string key, T value, string generationKey, TimeSpan? expiration = null, TimeSpan? slidingExpiration = null)
    {
        try
        {
            var userGenerationKey = $"{key}_generation";
            
            // Get or initialize current generation
            var (currentGenExists, currentGeneration) = await TryGetAsync<int>(generationKey);
            if (!currentGenExists)
            {
                currentGeneration = 1;
                await SetAsync(generationKey, currentGeneration);
            }

            // Set the value and the user's generation
            await SetAsync(key, value, expiration, slidingExpiration);
            await SetAsync(userGenerationKey, currentGeneration, expiration, slidingExpiration);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error setting cache with generation for key {Key}", key);
        }
    }

    public async Task InvalidateGenerationAsync(string generationKey)
    {
        try
        {
            var (exists, currentGeneration) = await TryGetAsync<int>(generationKey);
            var newGeneration = exists ? currentGeneration + 1 : 1;
            await SetAsync(generationKey, newGeneration);
            
            _logger.LogDebug("Incremented generation for key {GenerationKey} to {Generation}", generationKey, newGeneration);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error invalidating generation for key {GenerationKey}", generationKey);
        }
    }

    public async Task<IEnumerable<TenantDto>?> GetCachedUserTenantsAsync(Guid userId)
    {
        var cacheKey = $"user_tenants_{userId}";
        return await GetWithGenerationAsync<IEnumerable<TenantDto>>(cacheKey, UserTenantGenerationKey);
    }

    public async Task SetCachedUserTenantsAsync(Guid userId, IEnumerable<TenantDto> tenants)
    {
        var cacheKey = $"user_tenants_{userId}";
        await SetWithGenerationAsync(cacheKey, tenants, UserTenantGenerationKey, 
            TimeSpan.FromMinutes(UserTenantCacheMinutes), 
            TimeSpan.FromMinutes(UserTenantCacheMinutes / 2));
    }

    public async Task InvalidateCachedUserTenantsAsync(Guid userId)
    {
        var cacheKey = $"user_tenants_{userId}";
        await RemoveAsync(cacheKey);
        await RemoveAsync($"{cacheKey}_generation");
    }

    public async Task InvalidateAllCachedUserTenantsAsync()
    {
        await InvalidateGenerationAsync(UserTenantGenerationKey);
    }

    public async Task<IEnumerable<SiteDto>?> GetCachedUserSitesAsync(Guid userId, Guid tenantId)
    {
        var cacheKey = $"user_sites_{userId}_{tenantId}";
        return await GetWithGenerationAsync<IEnumerable<SiteDto>>(cacheKey, UserSiteGenerationKey);
    }

    public async Task SetCachedUserSitesAsync(Guid userId, Guid tenantId, IEnumerable<SiteDto> sites)
    {
        var cacheKey = $"user_sites_{userId}_{tenantId}";
        await SetWithGenerationAsync(cacheKey, sites, UserSiteGenerationKey,
            TimeSpan.FromMinutes(UserSiteCacheMinutes),
            TimeSpan.FromMinutes(UserSiteCacheMinutes / 2));
    }

    public async Task InvalidateCachedUserSitesAsync(Guid userId, Guid tenantId)
    {
        var cacheKey = $"user_sites_{userId}_{tenantId}";
        await RemoveAsync(cacheKey);
        await RemoveAsync($"{cacheKey}_generation");
    }

    public async Task InvalidateAllCachedUserSitesAsync()
    {
        await InvalidateGenerationAsync(UserSiteGenerationKey);
    }
}