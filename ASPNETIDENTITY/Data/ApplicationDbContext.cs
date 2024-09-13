using ASPNETIDENTITY.Domain.Entities;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace ASPNETIDENTITY.Data
{
    public class ApplicationDbContext : IdentityDbContext<ApplicationUser> // Update the base class to IdentityDbContext<ApplicationUser>
    {
        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options) : base(options)
        {
        }

        public DbSet<ApplicationUser> ApplicationUser { get; set; } // Update this line to use the correct namespace
    }
}
