using PlatformApi.Models.DTOs;

namespace PlatformApi.Common.Services;

public interface ICacheService
{
    /// <summary>
    /// Gets a cached item by key
    /// </summary>
    /// <typeparam name="T">The type of the cached item</typeparam>
    /// <param name="key">The cache key</param>
    /// <returns>The cached item or default if not found</returns>
    Task<T?> GetAsync<T>(string key);

    /// <summary>
    /// Sets a cached item with optional expiration
    /// </summary>
    /// <typeparam name="T">The type of the item to cache</typeparam>
    /// <param name="key">The cache key</param>
    /// <param name="value">The value to cache</param>
    /// <param name="expiration">Optional absolute expiration time</param>
    /// <param name="slidingExpiration">Optional sliding expiration time</param>
    /// <returns>Task representing the async operation</returns>
    Task SetAsync<T>(string key, T value, TimeSpan? expiration = null, TimeSpan? slidingExpiration = null);

    /// <summary>
    /// Removes a cached item by key
    /// </summary>
    /// <param name="key">The cache key to remove</param>
    /// <returns>Task representing the async operation</returns>
    Task RemoveAsync(string key);

    /// <summary>
    /// Removes all cached items matching a pattern (if supported by implementation)
    /// For memory cache, this may use generation-based invalidation
    /// </summary>
    /// <param name="pattern">The pattern to match keys against</param>
    /// <returns>Task representing the async operation</returns>
    Task RemoveByPatternAsync(string pattern);

    /// <summary>
    /// Gets a cached item with generation-based validation
    /// This method handles generation-based cache invalidation automatically
    /// </summary>
    /// <typeparam name="T">The type of the cached item</typeparam>
    /// <param name="key">The cache key</param>
    /// <param name="generationKey">The generation key for invalidation</param>
    /// <returns>The cached item or default if not found or invalidated</returns>
    Task<T?> GetWithGenerationAsync<T>(string key, string generationKey);

    /// <summary>
    /// Sets a cached item with generation tracking
    /// </summary>
    /// <typeparam name="T">The type of the item to cache</typeparam>
    /// <param name="key">The cache key</param>
    /// <param name="value">The value to cache</param>
    /// <param name="generationKey">The generation key for invalidation</param>
    /// <param name="expiration">Optional absolute expiration time</param>
    /// <param name="slidingExpiration">Optional sliding expiration time</param>
    /// <returns>Task representing the async operation</returns>
    Task SetWithGenerationAsync<T>(string key, T value, string generationKey, TimeSpan? expiration = null, TimeSpan? slidingExpiration = null);

    /// <summary>
    /// Invalidates all caches associated with a generation key by incrementing the generation
    /// </summary>
    /// <param name="generationKey">The generation key to invalidate</param>
    /// <returns>Task representing the async operation</returns>
    Task InvalidateGenerationAsync(string generationKey);

    // Domain-specific cache methods for User Tenants
    /// <summary>
    /// Gets cached user tenants with automatic key generation and cache invalidation handling
    /// </summary>
    /// <param name="userId">The user ID</param>
    /// <returns>The cached user tenants or null if not found/invalidated</returns>
    Task<IEnumerable<TenantDto>?> GetCachedUserTenantsAsync(Guid userId);

    /// <summary>
    /// Sets cached user tenants with automatic key generation and expiration
    /// </summary>
    /// <param name="userId">The user ID</param>
    /// <param name="tenants">The tenants to cache</param>
    /// <returns>Task representing the async operation</returns>
    Task SetCachedUserTenantsAsync(Guid userId, IEnumerable<TenantDto> tenants);

    /// <summary>
    /// Invalidates cached user tenants for a specific user
    /// </summary>
    /// <param name="userId">The user ID</param>
    /// <returns>Task representing the async operation</returns>
    Task InvalidateCachedUserTenantsAsync(Guid userId);

    /// <summary>
    /// Invalidates all cached user tenants across all users
    /// </summary>
    /// <returns>Task representing the async operation</returns>
    Task InvalidateAllCachedUserTenantsAsync();

    // Domain-specific cache methods for User Sites
    /// <summary>
    /// Gets cached user sites with automatic key generation and cache invalidation handling
    /// </summary>
    /// <param name="userId">The user ID</param>
    /// <param name="tenantId">The tenant ID</param>
    /// <returns>The cached user sites or null if not found/invalidated</returns>
    Task<IEnumerable<SiteDto>?> GetCachedUserSitesAsync(Guid userId, Guid tenantId);

    /// <summary>
    /// Sets cached user sites with automatic key generation and expiration
    /// </summary>
    /// <param name="userId">The user ID</param>
    /// <param name="tenantId">The tenant ID</param>
    /// <param name="sites">The sites to cache</param>
    /// <returns>Task representing the async operation</returns>
    Task SetCachedUserSitesAsync(Guid userId, Guid tenantId, IEnumerable<SiteDto> sites);

    /// <summary>
    /// Invalidates cached user sites for a specific user and tenant
    /// </summary>
    /// <param name="userId">The user ID</param>
    /// <param name="tenantId">The tenant ID</param>
    /// <returns>Task representing the async operation</returns>
    Task InvalidateCachedUserSitesAsync(Guid userId, Guid tenantId);

    /// <summary>
    /// Invalidates all cached user sites across all users
    /// </summary>
    /// <returns>Task representing the async operation</returns>
    Task InvalidateAllCachedUserSitesAsync();

    /// <summary>
    /// Checks if a key exists in the cache
    /// </summary>
    /// <param name="key">The cache key</param>
    /// <returns>True if the key exists, false otherwise</returns>
    Task<bool> ExistsAsync(string key);

    /// <summary>
    /// Tries to get a cached item by key
    /// </summary>
    /// <typeparam name="T">The type of the cached item</typeparam>
    /// <param name="key">The cache key</param>
    /// <returns>Tuple indicating success and the cached item</returns>
    Task<(bool Success, T? Value)> TryGetAsync<T>(string key);
}