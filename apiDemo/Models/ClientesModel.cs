using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace apiDemo.Models
{
    public class ClientesModel
    {
        public int id { get; set; }
        public string nombres { get; set; }
        public string apellidos { get; set; }
        public string direccion { get; set; }
        public DateTime fecha_creacion { get; set; }
    }
}
