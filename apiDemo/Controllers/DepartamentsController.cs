using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using apiDemo.Data;
using apiDemo.Models;


namespace apiDemo.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class DepartamentsController : ControllerBase
    {
        private readonly dbContext _context;
        public DepartamentsController (dbContext context)
        {
            _context = context;
        }

        //select departaments by id = id
        [HttpGet("idDepartament")]
        public async Task<ActionResult<CountryDepartametsModel>> GetModelDepartament(int idDepartament)
        {
            var departament = await _context.CountryDepartaments.FindAsync(idDepartament);
            if (departament == null)
            {
                return NotFound();
            }
            return departament;
        }

        //select departament by name = name paramet
        [HttpGet("nameDepartament")]
        public ActionResult<IEnumerable<CountryDepartametsModel>> GetModelDepartamentByName(string nameDepartament)
        {
            var departament = _context.CountryDepartaments.Where(x => x.name == nameDepartament)
                .Select(x => new
                {
                    id = x.id,
                    id_country = x.id_country,
                    name = x.name,
                    code = x.code,
                    date_created = x.date_created
                });
            if (departament == null)
            {
                return NotFound();
            }
            return Ok(departament);
        }

        //select departament by name = name country paramet
        [HttpGet("idCountry")]
        public ActionResult<IEnumerable<CountryDepartametsModel>> selectDepartamentByNameCountry(int idCountry)
        {
            var departament = _context.CountryDepartaments.Where(x => x.id_country == idCountry)
                .Select(x => new
                {
                    id = x.id,
                    id_country = x.id_country,
                    name = x.name,
                    code = x.code,
                    date_created = x.date_created
                });
            if (departament == null)
            {
                return NotFound();
            }
            return Ok(departament);
        }

        //selet * departament  db
        [HttpGet("getDepartaments")]
        public ActionResult getDepartaments()
        {
            try
            {
                var departament = _context.CountryDepartaments.Select(x => new
                {
                    id = x.id,
                    id_country = x.id_country,
                    name = x.name,
                    code = x.code,
                    date_created = x.date_created
                });
                return Ok(departament);
            }
            catch (Exception ex)
            {
                Console.WriteLine("an error ocurred" + ex.ToString());
                return BadRequest();
            }
        }

        //to created new departament
        [HttpPost("newDepartament")]
        public async Task<ActionResult<CountryDepartametsModel>> newDepartament(CountryDepartametsModel departamentModel)
        {
            try
            {
                departamentModel.date_created = DateTime.Now;
                _context.CountryDepartaments.Add(departamentModel);
                await _context.SaveChangesAsync();
                return CreatedAtAction("GetModelDepartament", new { id = departamentModel.id }, departamentModel);
            }
            catch (Exception ex)
            {
                Console.WriteLine("an error ocurred" + ex.ToString());
                return BadRequest(ex);
            }
        }

        //to update information the departament
        [HttpPut("updateDepartament")]
        public async Task<ActionResult<CountryModel>> updateDepartament(CountryDepartametsModel departamentModel)
        {
            try
            {
                var departament = _context.CountryDepartaments.FirstOrDefault(x => x.id == departamentModel.id);
                departament.name = departamentModel.name;
                departament.code = departamentModel.code;
                await _context.SaveChangesAsync();
                return CreatedAtAction("GetModelDepartament", new { id = departamentModel.id }, departamentModel);
            }
            catch (Exception ex)
            {
                Console.WriteLine("an error ocurred" + ex.ToString());
                return BadRequest();
            }
        }

        [HttpDelete("deleteDepartament")]
        public async Task<ActionResult> deleteDepartament(CountryDepartametsModel departamentModel)
        {
            try
            {
                var departament = _context.CountryDepartaments.FirstOrDefault(x => x.id == departamentModel.id);
                _context.CountryDepartaments.Remove(departament);
                await _context.SaveChangesAsync();
                return Ok();
            }
            catch (Exception ex)
            {
                Console.WriteLine("an error ocurred" + ex.ToString());
                return BadRequest();
            }
        }

        private bool ModelDepartamentExists(int id)
        {
            return _context.CountryDepartaments.Any(e => e.id == id);
        }
    }
}