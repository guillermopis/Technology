using System;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Serilog;
using Serilog.Events;
using Autofac.Extensions.DependencyInjection;


namespace apiDemo
{
    public class Program
    {
        public static void Main(string[] args)
        {
            var enviroment = Environment.GetEnvironmentVariable("ASPNETCORE_ENVIROMENT");
            if (enviroment == "Development" | enviroment == "QA")
            {
                Log.Logger = new LoggerConfiguration()
                    .Enrich.FromLogContext()
                    .MinimumLevel.Override("Microsoft", LogEventLevel.Warning)
                    .MinimumLevel.Override("System", LogEventLevel.Warning)
                    .MinimumLevel.Debug()
                    .WriteTo.Console(LogEventLevel.Information, "{NewLine}{Timestamp:HH:mm:ss} [{Level}] ({CorrelationToken}) {Message}{NewLine}{Exception}")
                    .CreateLogger();
            }
            try{
                CreateWebHostBuilder(args)
                    .ConfigureAppConfiguration((hostingContext, config) =>
                    {
                        var env = hostingContext.HostingEnvironment;
                        config
                        .AddJsonFile("appsettings.json", optional: true, reloadOnChange: true)
                        .AddJsonFile($"appsettings.{env.EnvironmentName}.json", optional: true, reloadOnChange: true);
                        config.AddEnvironmentVariables();
                        if (args != null)
                        {
                            config.AddCommandLine(args);
                        }
                    }).Build().Run();
            }
            finally
            {
                Log.CloseAndFlush();
            }
        }

        public static IWebHostBuilder CreateWebHostBuilder(string[] args) =>
            WebHost.CreateDefaultBuilder(args)
                .UseSerilog()
            .ConfigureServices(services => services.AddAutofac())
                .UseStartup<Startup>();
    }
}
