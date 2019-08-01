using System;
using apiDemo.Data;
using apiDemo.Infraestructure;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Autofac;
using Serilog;
using Swashbuckle.AspNetCore.Swagger;

namespace apiDemo
{
    public class Startup
    {
        public IConfiguration configuration { get;}
        private IOptions<appSettings> appSettings;
        private IOptions<connectionString> connectionString;

        public Startup(IConfiguration configuration)
        {
            this.configuration = configuration;
        }

        public void ConfigureContainer(ContainerBuilder builder)
        {
            builder.RegisterModule(new containerConfig<int, int>(appSettings.Value, Log.Logger));
        }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddMvc().SetCompatibilityVersion(CompatibilityVersion.Version_2_2);
            services.AddOptions();
            services.Configure<appSettings>(configuration.GetSection("security"));
            //configuration to Enviroment infraestructure
            var sp = services.BuildServiceProvider();
            appSettings = sp.GetService < IOptions<appSettings>>();

            //add service to sql repository
            services.AddDbContext<dbContext>(options =>
                options.UseSqlServer(Environment.GetEnvironmentVariable("CONNECTION_STRING"))
            );

            //configuration for cors
            services.AddCors(options =>
            {
                options.AddPolicy("ConfigurationCors", policyCors =>
                {
                    //policyCors.WithOrigins(appSettings.Value.allowedHosts) enable  to restrict access
                    policyCors.AllowAnyOrigin()
                    .AllowAnyHeader()
                    .AllowAnyMethod();
                });
            });

            // Register the Swagger generator, defining one or more Swagger documents
            services.AddSwaggerGen(swagger =>
            {
                var contact = new Contact() { Name = SwaggerConfiguration.ContactName, Url = SwaggerConfiguration.ContactUrl };
                swagger.SwaggerDoc(SwaggerConfiguration.DocNameV1,
                                   new Info
                                   {
                                       Title = SwaggerConfiguration.DocInfoTitle,
                                       Version = SwaggerConfiguration.DocInfoVersion,
                                       Description = SwaggerConfiguration.DocInfoDescription,
                                       Contact = contact
                                   }
                                    );
            });

        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IHostingEnvironment env)
        {
            // Enable middleware to serve generated Swagger as a JSON endpoint.
            app.UseSwagger();

            // Enable middleware to serve swagger-ui (HTML, JS, CSS, etc.), specifying the Swagger JSON endpoint.
            app.UseSwaggerUI(c =>
            {
                c.SwaggerEndpoint(SwaggerConfiguration.EndpointUrl, SwaggerConfiguration.EndpointDescription);
            });

            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            else
            {
                // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
                app.UseHsts();
            }

            app.UseCors("ConfigurationCors");
            app.UseHttpsRedirection();
            app.UseMvc();
        }
    }
}
