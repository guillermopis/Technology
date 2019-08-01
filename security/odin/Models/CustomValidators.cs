using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

namespace ExoGuardian.Models
{
    public class CustomValidators
    {
        /*
        public class NitIsValid : ValidationAttribute
        {
            protected override ValidationResult
                 IsValid(object value, ValidationContext validationContext)
            {

                var model = (Models.Customer)validationContext.ObjectInstance;

                string _nit = Convert.string(model.nit);

                regex regex = new regex("/^(\d+)-(\d|K)$/");

                Match match = regex.Match(_nit);

                if (match.Success)
                {
                    return ValidationResult.Success;
                }
                else
                {
                    return new ValidationResult
                     ("nit no válido");
                }
            }
        }
        */
    }

}
