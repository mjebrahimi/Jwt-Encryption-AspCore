using System;
using System.Text;
using JwtEncryption.Models;
using JwtEncryption.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;

namespace JwtEncryption
{
    public class Startup
    {
        public IConfiguration Configuration { get; }
        public JwtSettings JwtSettings { get; }

        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
            JwtSettings = Configuration.GetSection(nameof(JwtSettings)).Get<JwtSettings>();
        }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            services.Configure<JwtSettings>(Configuration.GetSection(nameof(JwtSettings)));

            services.AddTransient<IJwtService, JwtService>();

            services.AddMvc().SetCompatibilityVersion(CompatibilityVersion.Version_2_1);

            services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
                .AddJwtBearer(options =>
                {
                    var secretkey = Encoding.UTF8.GetBytes(JwtSettings.SecretKey);
                    var encryptionkey = Encoding.UTF8.GetBytes(JwtSettings.Encryptkey);

                    var validationParameters = new TokenValidationParameters
                    {
                        ClockSkew = TimeSpan.Zero, // default: 5 min
                        RequireSignedTokens = true,

                        ValidateIssuerSigningKey = true,
                        IssuerSigningKey = new SymmetricSecurityKey(secretkey),

                        RequireExpirationTime = true,
                        ValidateLifetime = true,

                        ValidateAudience = true, //default : false
                        ValidAudience = JwtSettings.Audience,

                        ValidateIssuer = true, //default : false
                        ValidIssuer = JwtSettings.Issuer,

                        TokenDecryptionKey = new SymmetricSecurityKey(encryptionkey)
                    };

                    options.RequireHttpsMetadata = false;
                    options.SaveToken = true;
                    options.TokenValidationParameters = validationParameters;
                });
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IHostingEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            else
            {
                app.UseHsts();
            }

            app.UseHttpsRedirection();

            app.UseAuthentication(); //middleware for authenticate request like verify token

            app.UseMvc();
        }
    }
}
