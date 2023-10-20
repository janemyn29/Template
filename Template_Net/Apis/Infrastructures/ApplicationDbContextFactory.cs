using Microsoft.EntityFrameworkCore.Design;
using Microsoft.EntityFrameworkCore;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Infrastructures
{
    public class ApplicationDbContextFactory /*: IDesignTimeDbContextFactory<AppDbContext>*/
    {
        /*public AppDbContext CreateDbContext(string[] args)
        {
            var optionsBuilder = new DbContextOptionsBuilder<AppDbContext>();
            optionsBuilder.UseSqlServer("LAPTOP-D5RP13A1;Initial Catalog=Warehouse;User ID=sa;Password=12345;Trust Server Certificate=true; MultipleActiveResultSets=true");

            return new AppDbContext(optionsBuilder.Options);
        }*/
    }
}
