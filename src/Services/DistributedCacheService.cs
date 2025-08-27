using System.Text.Json;
using Microsoft.Extensions.Caching.Distributed;
using PlatformApi.Models.DTOs;

namespace PlatformApi.Services;

public class DistributedCacheService : ICacheService
{
    private readonly IDistributedCache _distributedCache;
    private readonly ILogger<DistributedCacheService> _logger;
    private readonly JsonSerializerOptions _jsonOptions;

    public DistributedCacheService(IDistributedCache distributedCache, ILogger<DistributedCacheService> logger)
    {
        _distributedCache = distributedCache;
        _logger = logger;
        _jsonOptions = new JsonSerializerOptions
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            WriteIndented = false
        };
    }

    public async Task<T?> GetAsync<T>(string key)
    {
        try
        {
            var cachedValue = await _distributedCache.GetStringAsync(key);
            if (string.IsNullOrEmpty(cachedValue))
            {
                return default(T);
            }

            return JsonSerializer.Deserialize<T>(cachedValue, _jsonOptions);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error getting distributed cache key {Key}", key);
            return default(T);
        }
    }

    public async Task SetAsync<T>(string key, T value, TimeSpan? expiration = null, TimeSpan? slidingExpiration = null)
    {
        try
        {
            var serializedValue = JsonSerializer.Serialize(value, _jsonOptions);
            var options = new DistributedCacheEntryOptions();

            if (expiration.HasValue)
            {
                options.SetAbsoluteExpiration(expiration.Value);
            }

            if (slidingExpiration.HasValue)
            {
                options.SetSlidingExpiration(slidingExpiration.Value);
            }

            await _distributedCache.SetStringAsync(key, serializedValue, options);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error setting distributed cache key {Key}", key);
        }
    }

    public async Task RemoveAsync(string key)
    {
        try
        {
            await _distributedCache.RemoveAsync(key);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error removing distributed cache key {Key}", key);
        }
    }

    public Task RemoveByPatternAsync(string pattern)
    {
        try
        {
            // For Redis-based distributed cache, we could implement pattern removal
            // using Redis SCAN and DEL commands, but IDistributedCache doesn't expose this
            // For AWS ElastiCache Memcached, pattern removal isn't supported
            // We'll use generation-based invalidation approach similar to memory cache
            _logger.LogWarning("Pattern-based removal not directly supported in distributed cache for pattern: {Pattern}. Consider using generation-based invalidation.", pattern);
            
            // If this is Redis and we need pattern support, we could inject IConnectionMultiplexer
            // directly for Redis-specific operations, but that would break the abstraction
            // For now, we'll rely on the calling code to handle this scenario
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error removing distributed cache pattern {Pattern}", pattern);
        }
        
        return Task.CompletedTask;
    }

    public async Task<bool> ExistsAsync(string key)
    {
        try
        {
            var value = await _distributedCache.GetStringAsync(key);
            return !string.IsNullOrEmpty(value);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error checking distributed cache key existence {Key}", key);
            return false;
        }
    }

    public async Task<(bool Success, T? Value)> TryGetAsync<T>(string key)
    {
        try
        {
            var cachedValue = await _distributedCache.GetStringAsync(key);
            if (string.IsNullOrEmpty(cachedValue))
            {
                return (false, default(T));
            }

            var deserializedValue = JsonSerializer.Deserialize<T>(cachedValue, _jsonOptions);
            return (true, deserializedValue);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error trying to get distributed cache key {Key}", key);
            return (false, default(T));
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
            _logger.LogError(ex, "Error getting distributed cache with generation for key {Key}", key);
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
            _logger.LogError(ex, "Error setting distributed cache with generation for key {Key}", key);
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
            _logger.LogError(ex, "Error invalidating distributed cache generation for key {GenerationKey}", generationKey);
        }
    }

    // Domain-specific cache methods for User Tenants
    private const string UserTenantGenerationKey = "user_tenant_cache_generation";
    private const int UserTenantCacheMinutes = 5;

    // Domain-specific cache methods for User Sites
    private const string UserSiteGenerationKey = "user_site_cache_generation";
    private const int UserSiteCacheMinutes = 5;

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