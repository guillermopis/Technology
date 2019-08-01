using IdentityModel;
using System;
using System.IO;
using IdentityServer4;
using IdentityServer4.Models;
using System.Collections.Generic;
using static IdentityServer4.IdentityServerConstants;
using IdentityServer4.Test;

namespace ExoGuardian.InMemory
{
    public static class config
    {
        public static IEnumerable<IdentityResource> getIdentityResources()
        {
            return new List<IdentityResource>
            {
                new IdentityResources.OpenId(),
                new IdentityResources.Profile(),
                new IdentityResource("roles", new List<string>{ JwtClaimTypes.Role , JwtClaimTypes.Audience })
            };
        }

        public static IEnumerable<ApiResource> getApiResources()
        {
            return new List<ApiResource>
            {
                new ApiResource("Gilgamesh", "Backend RESTful Api")
                {
                    UserClaims=new List<string> { "roles" },
                },
                new ApiResource("api2", "IdentityManagement"),
                new ApiResource("api3", "api3")
                {
                    ApiSecrets=
                    {
                        new Secret("secreto".Sha256())
                    },
                    Scopes = {
                        new Scope("test")
                    }
                }
            };
        }

        public static IEnumerable<Client> getClients()
        {
            return new List<Client>
            {
                new Client {
                    ClientId = "skyfront",
                    ClientName = "Frontend",
                    RequireConsent=false,
                    AllowedGrantTypes=GrantTypes.Implicit,
                    AlwaysIncludeUserClaimsInIdToken = true,
                    AllowAccessTokensViaBrowser = true,
                    ClientSecrets =
                    {
                        new Secret("Secreto@3#2!2019".Sha256())
                    },
                    
                    AllowedScopes=new List<String>{"api3",StandardScopes.OpenId,StandardScopes.Profile,"roles","Gilgamesh"},
                    AllowedCorsOrigins = {Environment.GetEnvironmentVariable("CORS_ORIGIN") },
                    RedirectUris = {Environment.GetEnvironmentVariable("CORS_REDIRECT_URI1"),Environment.GetEnvironmentVariable("CORS_REDIRECT_URI2")},
                    PostLogoutRedirectUris = { Environment.GetEnvironmentVariable("POST_LOGOUT")},
                    IdentityTokenLifetime = 300,
                    AllowOfflineAccess = true
                },
                new Client
                {
                    ClientId = "ethos",
                    ClientName = "Identity Manager UI",
                    AllowedGrantTypes = GrantTypes.ImplicitAndClientCredentials,
                    AlwaysIncludeUserClaimsInIdToken=true,
                    AllowAccessTokensViaBrowser=true,
                    RequireConsent = false,
                    ClientSecrets =
                    {
                        new Secret("Secreto@3#2!2019".Sha256())
                    },
                    // where to redirect to after login
                    RedirectUris = { Environment.GetEnvironmentVariable("LINK_ETHOS_LOGIN") },
                    // where to redirect to after logout
                    PostLogoutRedirectUris = { Environment.GetEnvironmentVariable("LINK_ETHOS_LOGOUT") },
                    AllowedScopes = new List<string>
                    {
                        StandardScopes.OpenId,
                        StandardScopes.Profile,
                        "roles", "api2"
                    },
                    AllowOfflineAccess = true
                }
            };
        }
    }
}
