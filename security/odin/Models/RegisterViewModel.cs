using System.ComponentModel.DataAnnotations;

namespace ExoGuardian.Models
{
    public class registerViewModel
    {
        [Required (ErrorMessage ="Correo electronico es requerido")]
        [EmailAddress]
        [Display(Name = "Email")]
        public string email { get; set; }

        [Required (ErrorMessage ="La Contraseña es requerida")]
        [StringLength(100, ErrorMessage = "La contraseña debe contener al menos 8 caracteres", MinimumLength = 8)]
        [DataType(DataType.Password)]
        [Display(Name = "Password")]
        public string Password { get; set; }

        [DataType(DataType.Password)]
        [Display(Name = "Confirm password")]
        [Compare("Password", ErrorMessage = "Las contraseñas no son iguales")]
        public string confirmPassword { get; set; }


        [Display(Name = "IsAdmin")]
        public bool isAdmin { get; set; }
    }
}
