using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace apiDemo.Models
{
    public class CountryModel
    {
        public int id { get; set; }
        public string name { get; set; }
        public string alfa_2 { get; set; }
        public string alfa_3 { get; set; }
        public string numeric_code { get; set; }
        public string link_iso { get; set; }
        public DateTime date_created { get; set; }
    }
}
