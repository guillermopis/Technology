using IdentityServer4.Quickstart.UI;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace ExoGuardian.Extensions
{
    public static class UrlHelperExtensions
    {
        public static string EmailConfirmationLink(this IUrlHelper urlHelper, string userId, string code, string scheme)
        {
           // System.Diagnostics.Debug.Write(urlHelper + userId + code + scheme + "inicia el email confirmation link kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkk");
            return urlHelper.Action(

        action: nameof(AccountController.ConfirmEmail),
                controller: "Account",
                values: new { userId, code },
                protocol: scheme);
            // System.Diagnostics.Debug.Write("devuelve helper action kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkk");
        }

        public static string ResetPasswordCallbackLink(this IUrlHelper urlHelper, string userId, string code, string scheme)
        {
            return urlHelper.Action(
                action: nameof(AccountController.ResetPassword),
                controller: "Account",
                values: new { userId, code },
                protocol: scheme);
        }
    }
}
