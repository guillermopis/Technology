using System;
using Autofac;
using Serilog;

namespace apiDemo.Infraestructure
{
    public sealed class containerConfig<TC,TI> : Module
        where TI : struct, IEquatable<TI>
        where TC : struct
    {
        private readonly appSettings appSettings;
        private readonly connectionString connectionStrings;
        private readonly ILogger logger;

        public containerConfig(appSettings appSettings, ILogger logger)
        {
            this.appSettings = appSettings;
            this.logger = logger;
        }
    }

}
