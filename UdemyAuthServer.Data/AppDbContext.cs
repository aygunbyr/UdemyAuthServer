using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using UdemyAuthServer.Core.Models;

namespace UdemyAuthServer.Data
{
    public class AppDbContext : IdentityDbContext<UserApp,IdentityRole,string>
    {
        public DbSet<Product> Products;
        public DbSet<UserRefreshToken> UserRefreshTokens;
        public AppDbContext(DbContextOptions<AppDbContext> options) : base(options)
        {
        }

        protected override void OnModelCreating(ModelBuilder builder)
        {
            builder.ApplyConfigurationsFromAssembly(GetType().Assembly);

            base.OnModelCreating(builder);
        }
    }
}
