using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using AspNetCore2AuthBoilerplate.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;

namespace AspNetCore2AuthBoilerplate
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        public void ConfigureServices(IServiceCollection services)
        {
            // Redis caching
            services.AddDistributedRedisCache(options =>
            {
                options.Configuration = Configuration.GetConnectionString("Redis");
                options.InstanceName = "aspnetcore2authboilerplate";
            });

            // Authentication
            var scheme = CookieAuthenticationDefaults.AuthenticationScheme;
            //var jwtScheme = JwtBearerDefaults.AuthenticationScheme;
            services.AddAuthentication(scheme) // 1. Set the scheme we're going to use
                .AddCookie(scheme) // 2. Add cookie authentication (same scheme as above)
                //.AddJwtBearer(jwtScheme, options =>
                //{
                //    options.SaveToken = true; // save token in AuthenticationProperties for easy retrieval
                //    options.TokenValidationParameters = new TokenValidationParameters
                //    {
                //        ValidIssuer = Configuration["Authentication:Tokens:Issuer"],
                //        ValidAudience = Configuration["Authentication:Tokens:Issuer"],
                //        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(Configuration["Authentication:Tokens:Key"]))
                //    };
                //})
                .AddGoogle("Google", options => // 3. Add social logins
                {
                    options.ClientId = Configuration["Authentication:Google:ClientId"];
                    options.ClientSecret = Configuration["Authentication:Google:ClientSecret"];
                    options.SignInScheme = scheme;
                    options.Events.OnTicketReceived = HandleOnTicketReceived;
                })
                .AddMicrosoftAccount("Microsoft", options =>
                {
                    // ApplicationId and Password are used on the Microsoft Dev Portal,
                    // but they're actually mapped as ClientId and Secret
                    options.ClientId = Configuration["Authentication:Microsoft:ApplicationId"];
                    options.ClientSecret = Configuration["Authentication:Microsoft:Password"];
                    options.SignInScheme = scheme;
                    options.Events.OnTicketReceived = HandleOnTicketReceived;
                })
                .AddFacebook("Facebook", options =>
                {
                    options.AppId = Configuration["Authentication:Facebook:AppId"];
                    options.AppSecret = Configuration["Authentication:Facebook:AppSecret"];
                    options.SignInScheme = scheme;
                    options.Events.OnTicketReceived = HandleOnTicketReceived;
                })
                .AddTwitter("Twitter", options =>
                {
                    options.ConsumerKey = Configuration["Authentication:Twitter:ConsumerKey"];
                    options.ConsumerSecret = Configuration["Authentication:Twitter:ConsumerSecret"];
                    options.SignInScheme = scheme;
                    options.Events.OnTicketReceived = HandleOnTicketReceived;
                });

            services.AddSingleton<IUsersService, UsersService>();
            services.AddMvc();
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
                app.UseExceptionHandler("/Error");
            }

            app.UseAuthentication();

            app.UseStaticFiles();

            app.UseMvc(routes =>
            {
                routes.MapRoute(
                    name: "default",
                    template: "{controller=Home}/{action=Index}/{id?}");
            });
        }

        private Task HandleOnTicketReceived(TicketReceivedContext context)
        {
            // Get the principal identity
            var identity = context.Principal.Identities.First();
            // Grab the email address
            var emailAddress = identity.Claims.FirstOrDefault(c => c.Type == ClaimTypes.Email).Value;

            // Here, we can use the e-mail address to verify user state in our own database, attach any claims or transform the identity prior to stamping the cookie

            // Continue with the pipeline
            return Task.CompletedTask;
        }
    }
}
