using Domain.Entities;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Infrastructures
{
    public class ApplicationDbContextInitialiser
    {
        private readonly ILogger<ApplicationDbContextInitialiser> _logger;
        private readonly AppDbContext _context;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;

        public ApplicationDbContextInitialiser(ILogger<ApplicationDbContextInitialiser> logger, AppDbContext context, UserManager<ApplicationUser> userManager, RoleManager<IdentityRole> roleManager)
        {
            _logger = logger;
            _context = context;
            _userManager = userManager;
            _roleManager = roleManager;
        }

        public async Task InitialiseAsync()
        {
            try
            {
                if (_context.Database.IsSqlServer())
                {
                    await _context.Database.MigrateAsync();
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "An error occurred while initialising the database.");
                throw;
            }
        }

        public async Task SeedAsync()
        {
            try
            {
                await TrySeedAsync();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "An error occurred while seeding the database.");
                throw;
            }
        }
        public async Task TrySeedAsync()
        {
            var managerRole = new IdentityRole("Admin");

            if (_roleManager.Roles.All(r => r.Name != managerRole.Name))
            {
                await _roleManager.CreateAsync(managerRole);
            }

            // staff roles
            var staffRole = new IdentityRole("Staff");

            if (_roleManager.Roles.All(r => r.Name != staffRole.Name))
            {
                await _roleManager.CreateAsync(staffRole);
            }

            // customer roles
            var customerRole = new IdentityRole("Customer");

            if (_roleManager.Roles.All(r => r.Name != customerRole.Name))
            {
                await _roleManager.CreateAsync(customerRole);
            }
            
            // sale roles
            var saleRole = new IdentityRole("Saler");

            if (_roleManager.Roles.All(r => r.Name != customerRole.Name))
            {
                await _roleManager.CreateAsync(customerRole);
            }

            // admin users
            var administrator = new ApplicationUser { UserName = "admin@localhost", Email = "admin@localhost", Fullname = "Admin", Avatar = "(null)", Address = "no", Birthday = DateTime.Parse("2000-01-01") };

            if (_userManager.Users.All(u => u.UserName != administrator.UserName))
            {
                await _userManager.CreateAsync(administrator, "Admin123456!");
                if (!string.IsNullOrWhiteSpace(managerRole.Name))
                {
                    await _userManager.AddToRolesAsync(administrator, new[] { managerRole.Name });
                }
            }

        }
    }
}
