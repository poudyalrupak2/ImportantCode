
using ImportantCode.Data;
using ImportantCode.Entity;
using ImportantCode.Infrastructure;
using ImportantCode.Service;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using System.Reflection;
using System.Text;

namespace ImportantCode
{
    public class Program
    {
        public static void Main(string[] args)
        {
            var builder = WebApplication.CreateBuilder(args);

            // Add services to the container.
            builder.Services.AddCors();
            builder.Services.AddControllers();
            // Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
            builder.Services.AddEndpointsApiExplorer();
            builder.Services.AddSwaggerGen(
              c =>
              {
                  c.SwaggerDoc("v1", new OpenApiInfo { Title = "My API", Version = "v1" });
                  c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
                  {
                      In = ParameterLocation.Header,
                      Description = "Please enter token",
                      Name = "Authorization",
                      Type = SecuritySchemeType.Http,
                      BearerFormat = "JWT",
                      Scheme = "bearer"
                  });
                  c.AddSecurityRequirement(new OpenApiSecurityRequirement
                  {
                        {
                    new OpenApiSecurityScheme
                    {
                        Reference = new OpenApiReference
                        {
                            Type=ReferenceType.SecurityScheme,
                            Id="Bearer"
                        }
                    },
                    new string[]{}
                                }
                          });
                  c.ResolveConflictingActions(apiDescriptions => apiDescriptions.First());
                  var xmlfile = $"{Assembly.GetExecutingAssembly().GetName().Name}.xml";
                  var xmlfilefullpath = Path.Combine(AppContext.BaseDirectory, xmlfile);
                  c.IncludeXmlComments(xmlfilefullpath);
              });
            builder.Services.AddDbContext<ImportantCodeDbContext>(opts => opts.UseSqlServer(builder.Configuration["ConnectionString:DefaultConnection"]));
            builder.Services.AddIdentity<User, IdentityRole>(options =>
            {
                options.User.RequireUniqueEmail = true;
                options.User.AllowedUserNameCharacters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_";

                options.Password.RequiredLength = 6;
                options.Password.RequireDigit = false;
                options.Password.RequireLowercase = false;
                options.Password.RequireNonAlphanumeric = false;
                options.Password.RequireUppercase = false;
                

            })
               .AddEntityFrameworkStores<ImportantCodeDbContext>()
               .AddDefaultTokenProviders();

        



            var jwtTokenConfig = builder.Configuration.GetSection("jwtTokenConfig").Get<JwtTokenConfig>()!;
            builder.Services.AddSingleton(jwtTokenConfig);
            builder.Services.AddAuthentication(x =>
            {
                x.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
                x.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
            }).AddJwtBearer(x =>
            {
                x.RequireHttpsMetadata = true;
                x.SaveToken = true;
                x.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuer = true,
                    ValidIssuer = jwtTokenConfig.Issuer,
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(jwtTokenConfig.Secret)),
                    ValidAudience = jwtTokenConfig.Audience,
                    ValidateAudience = true,
                    ValidateLifetime = true,
                    ClockSkew = TimeSpan.FromMinutes(1)
                };
            });

            // Register services
            builder.Services.AddScoped<IJwtAuthManager, JwtAuthManager>();
            builder.Services.AddHostedService<JwtRefreshTokenCache>();
            var app = builder.Build();

            // Configure the HTTP request pipeline.
            if (app.Environment.IsDevelopment())
            {
                app.UseSwagger();
                app.UseSwaggerUI();
            }

            app.UseAuthorization();


            app.MapControllers();
            app.UseCors();
            app.UseAuthentication();
            app.UseAuthorization();
            app.Run();
        }
    }
}