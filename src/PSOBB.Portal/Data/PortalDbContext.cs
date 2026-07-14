using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace PSOBB.Portal.Data;

public sealed class PortalDbContext(DbContextOptions<PortalDbContext> options)
    : IdentityDbContext<PortalUser, PortalRole, Guid>(options)
{
    public DbSet<Invite> Invites => Set<Invite>();
    public DbSet<GameAccountLink> GameAccountLinks => Set<GameAccountLink>();
    public DbSet<ProvisioningRequest> ProvisioningRequests => Set<ProvisioningRequest>();
    public DbSet<AuditEvent> AuditEvents => Set<AuditEvent>();

    protected override void OnModelCreating(ModelBuilder builder)
    {
        base.OnModelCreating(builder);

        builder.Entity<PortalUser>()
            .Property(value => value.CreatedAt)
            .HasConversion(
                value => value.ToUnixTimeMilliseconds(),
                value => DateTimeOffset.FromUnixTimeMilliseconds(value));

        builder.Entity<Invite>(entity =>
        {
            entity.HasKey(value => value.Id);
            entity.Property(value => value.TokenHash).HasMaxLength(64).IsRequired();
            entity.HasIndex(value => value.TokenHash).IsUnique();
            entity.HasIndex(value => new { value.ExpiresAt, value.RedeemedAt });
        });

        builder.Entity<GameAccountLink>(entity =>
        {
            entity.HasKey(value => value.Id);
            entity.Property(value => value.GameUsername).HasMaxLength(16).IsRequired();
            entity.Property(value => value.NewservAccountId).HasMaxLength(64);
            entity.Property(value => value.State).HasConversion<string>().HasMaxLength(24);
            entity.Property(value => value.Version).IsConcurrencyToken();
            entity.Property(value => value.CreatedAt).HasConversion(
                value => value.ToUnixTimeMilliseconds(),
                value => DateTimeOffset.FromUnixTimeMilliseconds(value));
            entity.Property(value => value.UpdatedAt).HasConversion(
                value => value.ToUnixTimeMilliseconds(),
                value => DateTimeOffset.FromUnixTimeMilliseconds(value));
            entity.HasIndex(value => value.PortalUserId).IsUnique();
            entity.HasIndex(value => value.GameUsername).IsUnique();
            entity.HasOne(value => value.PortalUser)
                .WithOne(value => value.GameAccountLink)
                .HasForeignKey<GameAccountLink>(value => value.PortalUserId)
                .OnDelete(DeleteBehavior.Cascade);
        });

        builder.Entity<ProvisioningRequest>(entity =>
        {
            entity.HasKey(value => value.RequestId);
            entity.Property(value => value.Operation).HasMaxLength(32).IsRequired();
            entity.Property(value => value.State).HasConversion<string>().HasMaxLength(24);
            entity.Property(value => value.Version).IsConcurrencyToken();
            entity.Property(value => value.ErrorCode).HasMaxLength(64);
            entity.Property(value => value.CreatedAt).HasConversion(
                value => value.ToUnixTimeMilliseconds(),
                value => DateTimeOffset.FromUnixTimeMilliseconds(value));
            entity.Property(value => value.UpdatedAt).HasConversion(
                value => value.ToUnixTimeMilliseconds(),
                value => DateTimeOffset.FromUnixTimeMilliseconds(value));
            entity.HasIndex(value => new { value.PortalUserId, value.CreatedAt });
        });

        builder.Entity<AuditEvent>(entity =>
        {
            entity.HasKey(value => value.Id);
            entity.Property(value => value.EventType).HasMaxLength(64).IsRequired();
            entity.Property(value => value.Outcome).HasMaxLength(32).IsRequired();
            entity.Property(value => value.TargetId).HasMaxLength(128);
            entity.Property(value => value.SourceAddressHash).HasMaxLength(64);
            entity.Property(value => value.CreatedAt).HasConversion(
                value => value.ToUnixTimeMilliseconds(),
                value => DateTimeOffset.FromUnixTimeMilliseconds(value));
            entity.HasIndex(value => value.CreatedAt);
            entity.HasIndex(value => value.CorrelationId);
        });
    }
}
