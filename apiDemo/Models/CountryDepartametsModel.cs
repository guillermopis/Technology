using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace apiDemo.Models
{
    public class CountryDepartametsModel
    {
        public int id { get; set; }
        public int id_country { get; set; }
        public string name { get; set; }
        public string code { get; set; }
        public DateTime date_created { get; set; }
    }
}
