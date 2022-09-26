using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using DatingApp.API.Data.Entities;
using Microsoft.EntityFrameworkCore;

namespace DatingApp.API.Data
{
  public class DataContext : DbContext
  {
    public DataContext(DbContextOptions<DataContext> options) : base(options) { }
    
    public DbSet<User> AppUsers { get; set; }
  }
}