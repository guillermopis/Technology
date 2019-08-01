using ExoGuardian.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using System.Security.Claims;
using System.Threading.Tasks;

namespace ExoGuardian.Quickstart
{
    public class AppClaimsPrincipalFactory : UserClaimsPrincipalFactory<ApplicationUser, IdentityRole>
    {
        public AppClaimsPrincipalFactory(
        UserManager<ApplicationUser> userManager
        , RoleManager<IdentityRole> roleManager
        , IOptions<IdentityOptions> optionsAccessor)
    : base(userManager, roleManager, optionsAccessor)
        { }

        public async override Task<ClaimsPrincipal> CreateAsync(ApplicationUser user)
        {
            var principal = await base.CreateAsync(user);

            if (!string.IsNullOrWhiteSpace(user.UserName))
            {
                ((ClaimsIdentity)principal.Identity).AddClaims(new[] {
                 new Claim(ClaimTypes.GivenName, user.UserName)
            });
        }

             

            return principal;
        }
    }
}
