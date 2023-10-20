using Infrastructures;
using WebAPI.Middlewares;
using WebAPI;
using Application.Commons;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using Domain.Entities;
using Microsoft.AspNetCore.Identity;

var builder = WebApplication.CreateBuilder(args);

//builder.Environment.EnvironmentName = "Staging"; //for branch develop
//builder.Environment.EnvironmentName = "Production"; //for branch domain 
builder.Configuration
    .AddJsonFile("appsettings.json", false, true)
    .AddJsonFile($"appsettings.{builder.Environment.EnvironmentName}.json", false, true)
    .AddUserSecrets<Program>(true, false)
    .Build();

var MyAllowSpecificOrigins = "_myAllowSpecificOrigins";
builder.Services.AddCors(options =>
{
    options.AddPolicy(name: MyAllowSpecificOrigins,
                      policy =>
                      {
                          policy.WithOrigins("*"
                                              )
                                                .AllowAnyHeader()
                                                .AllowAnyMethod();

                      });
});

// parse the configuration in appsettings
var configuration = builder.Configuration.Get<AppConfiguration>();
builder.Services.AddInfrastructuresService(builder.Configuration, builder.Environment);
builder.Services.AddWebAPIService();
builder.Services.AddSingleton(configuration);
/*
    register with singleton life time
    now we can use dependency injection for AppConfiguration
*/
builder.Services.AddSingleton(configuration);

builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
}).AddJwtBearer(options =>
{
    options.SaveToken = true;
    options.RequireHttpsMetadata = false;
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidateAudience = true,
        ValidAudience = builder.Configuration["JWT:ValidAudience"],
        ValidIssuer = builder.Configuration["JWT:ValidIssuer"],
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(builder.Configuration["JWT:SecrectKey"]))

    };
});
var app = builder.Build();

app.UseCors(MyAllowSpecificOrigins);

// Initialise and seed database
using (var scope = app.Services.CreateScope())
{
    var _roleManager = scope.ServiceProvider.GetRequiredService<RoleManager<IdentityRole>>();
   
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
    
}

using (var scope = app.Services.CreateScope())
{
    var administrator = new ApplicationUser { UserName = "admin@localhost", Email = "admin@localhost", Fullname = "Admin", Avatar = "(null)", Address = "no", Birthday = DateTime.Parse("2000-01-01") };
    var _userManager = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
    if (_userManager.Users.All(u => u.UserName != administrator.UserName))
    {
        await _userManager.CreateAsync(administrator, "Admin@123");
        if (!string.IsNullOrWhiteSpace("Admin"))
        {
            await _userManager.AddToRolesAsync(administrator, new[] { "Admin" });
        }
    }
}

    // Configure the HTTP request pipeline.
    if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseMiddleware<GlobalExceptionMiddleware>();
app.UseMiddleware<PerformanceMiddleware>();
app.MapHealthChecks("/healthchecks");
app.UseHttpsRedirection();
// todo authentication
app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

app.Run();

// this line tell intergrasion test
// https://stackoverflow.com/questions/69991983/deps-file-missing-for-dotnet-6-integration-tests
public partial class Program { }

