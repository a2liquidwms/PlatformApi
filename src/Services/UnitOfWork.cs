using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.EntityFrameworkCore;
using PlatformApi.Models.BaseModels;

namespace PlatformApi.Services
{
    public interface IUnitOfWork<TContext> where TContext : DbContext
    {
        Task CompleteAsync();
    }

    public class UnitOfWork<TContext> : IUnitOfWork<TContext> where TContext : DbContext
    {
        private readonly TContext _context;
        private readonly IHttpContextAccessor _httpContextAccessor;

        public UnitOfWork(TContext context, IHttpContextAccessor httpContextAccessor)
        {
            _context = context;
            _httpContextAccessor = httpContextAccessor;
        }

        public async Task CompleteAsync()
        {
            var now = DateTime.UtcNow;
            var currentUser = _httpContextAccessor.HttpContext?.User.FindFirstValue(JwtRegisteredClaimNames.Email);

            foreach (var changedEntity in _context.ChangeTracker.Entries())
            {
                if (changedEntity.Entity is IBaseObject entity)
                {
                    entity.ModifiedSource ??= "app";
                    entity.LastModifiedDate = now;
                    entity.LastModifiedBy = currentUser;
                    switch (changedEntity.State)
                    {
                        case EntityState.Added:
                            entity.CreateDate = now;
                            entity.CreatedBy = currentUser;
                            break;
                        case EntityState.Modified:
                            _context.Entry(entity).Property(x => x.CreateDate).IsModified = false;
                            _context.Entry(entity).Property(x => x.CreatedBy).IsModified = false;
                            break;
                    }
                }
            }
            await _context.SaveChangesAsync();
        }
    }
}