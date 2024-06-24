using ImportantCode.Entity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace ImportantCode.Data
{
    public class ImportantCodeDbContext: IdentityDbContext<User>
    {
        public ImportantCodeDbContext(DbContextOptions<ImportantCodeDbContext> options):base(options)
        {

        }
        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            base.OnModelCreating(modelBuilder);
            modelBuilder.Entity<RefreshToken>(entity =>
            {
                entity.HasKey(e => e.Id);
                entity.Property(e => e.TokenString).IsRequired();
                entity.Property(e => e.UserName).IsRequired();
                entity.Property(e => e.ExpireAt).IsRequired();

                entity.HasOne(e => e.User)
                    .WithMany(u => u.RefreshTokens)
                    .HasForeignKey(e => e.UserId)
                    .OnDelete(DeleteBehavior.Cascade);
            });


        }
        public DbSet<RefreshToken> RefreshToken { get; set; }
    }
}