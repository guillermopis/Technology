using IdentityManager2.AspNetIdentity;
using System;
using System.IO;
using IdentityManager2.Configuration;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using System.IdentityModel.Tokens.Jwt;
using System.Threading.Tasks;

namespace Ethos
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            this.configuration = configuration;
        }

        public IConfiguration configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        // For more information on how to configure your application, visit https://go.microsoft.com/fwlink/?LinkID=398940
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddIdentityManager(opt =>
                    opt.SecurityConfiguration =
                        new SecurityConfiguration
                        {
                            HostAuthenticationType = "Cookies",
                            HostChallengeType = "oidc"
                        }).AddIdentityMangerService<AspNetCoreIdentityManagerService<IdentityUser, string, IdentityRole, string>>();
            services.AddDbContext<IdentityDbContext>(opt => opt.UseSqlServer(Environment.GetEnvironmentVariable("STRING_CONNECTION")));
            //services.AddDbContext<IdentityDbContext>(opt => opt.UseNpgsql(Environment.GetEnvironmentVariable("STRING_CONNECTION")));

            services.AddIdentity<IdentityUser, IdentityRole>()
              .AddEntityFrameworkStores<IdentityDbContext>()
              .AddDefaultTokenProviders();

            JwtSecurityTokenHandler.DefaultInboundClaimTypeMap.Clear();

            services.AddAuthentication()
                .AddCookie("Cookies")
                .AddOpenIdConnect("oidc", opt =>
                {
                    opt.Authority = Environment.GetEnvironmentVariable("LINK_EXO_GUARDIAN");
                    opt.ClientId = "ethos";
                    opt.ClientSecret = "Secreto@3#2!2019";
                    // default: openid & profile
                    opt.Scope.Add("roles");

                    opt.RequireHttpsMetadata = false; // dev only
                    opt.SignInScheme = "Cookies";
                    opt.CallbackPath = "/signin-oidc";

                    opt.Events = new OpenIdConnectEvents
                    {
                        OnTokenValidated = context => Task.CompletedTask
                    };
                });
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IHostingEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            app.UseAuthentication();
            app.UseIdentityManager();

            //app.Run(async (context) =>
            //{
            //    await context.Response.WriteAsync("Hello World!");
            //});
        }
    }
}
