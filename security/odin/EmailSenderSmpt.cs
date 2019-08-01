using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Mail;
using System.Threading.Tasks;

namespace ExoGuardian
{
    public class EmailSenderSmpt
    {


        public EmailSenderSmpt()
        {

        }

        public AuthMessageSenderOptions Options { get; }
        public string SendEmailAsync2(string email, string subject, string message)
        {
            System.Diagnostics.Debug.Write("inicia el email sender kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkk");
           return Execute2(subject, message, email);
            // return Execute( subject, message, email);
        }

        public string Execute2(string subjects, string message, string email)

        {
            //var client = new SendGridClient(apiKey);
            string msg="";
            MailMessage email2 = new MailMessage();

            email2.To.Add(email);
            email2.From = new MailAddress(Environment.GetEnvironmentVariable("EMAIL_ADDRESS"));
            email2.Subject = subjects;
            email2.SubjectEncoding = System.Text.Encoding.UTF8;
            email2.Body = message;
            email2.IsBodyHtml = true;
            email2.Priority = MailPriority.Normal;

            SmtpClient smtp = new SmtpClient();
            smtp.Port = 587;
            smtp.EnableSsl = true;
            smtp.UseDefaultCredentials = false;
            smtp.Credentials = new NetworkCredential(Environment.GetEnvironmentVariable("EMAIL_ADDRESS"), Environment.GetEnvironmentVariable("PASSWORD"));
            smtp.Host = "smtp.gmail.com";

            string output = null;



            try
            {
                smtp.Send(email2);
                email2.Dispose();
                //return 
                //output = "Corre electrónico fue enviado satisfactoriamente.";
                msg = " Te hemos enviado un mensaje de confirmacion a tu correo electronico";
            }
            catch (Exception ex)
            {
                output = "Error enviando correo electrónico: " + ex.Message;
                msg = "No se ha podido enviar el codigo de confirmacion, intente de nuevo mas tarde";
            }

            // client.SendEmailAsync(null);

            return msg;

        
    }
}
}
