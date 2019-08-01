using apiDemo.Models;
using Microsoft.EntityFrameworkCore;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace apiDemo.Data
{
    public class dbContext : DbContext
    {
        public dbContext(DbContextOptions<dbContext> options)
            : base(options)
        {

        }
        public DbSet<CountryDepartametsModel> CountryDepartaments { get; set; }
        public DbSet<CountryModel> country { get; set; }

    }
}
