using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using apiDemo.Data;
using apiDemo.Models;
using Microsoft.AspNetCore.Authorization;

namespace apiDemo.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    //[Authorize("apiPolicy")]
    public class CountryController : ControllerBase
    {
        private readonly dbContext _context;
        public CountryController (dbContext context)
        {
            _context = context;
        }

        //select country by id = id paramet
        [HttpGet("id")]
        public async Task<ActionResult<CountryModel>> GetModelCountry(int id)
        {
            var country = await _context.country.FindAsync(id);
            if (country == null)
            {
                return NotFound();
            }
            return country;
        }

        //select country by name = name paramet
        [HttpGet("name")]
        public  ActionResult<IEnumerable<CountryModel>> GetModelCountryByName(string name)
        {
            var country =  _context.country.Where(x => x.name == name)
                .Select(x => new
                {
                    id = x.id,
                    name = x.name,
                    alfa_2 = x.alfa_2,
                    alfa_3 = x.alfa_3,
                    numeri_code = x.numeric_code,
                    link_iso = x.link_iso,
                    date_created = x.date_created
                });
            if (country == null)
            {
                return NotFound();
            }
            return Ok(country);
        }

        //select country by code_alfa 2 = name paramet
        [HttpGet("codeAlfa")]
        public ActionResult<IEnumerable<CountryModel>> GetModelCountryAlfa_2(string code_alfa)
        {
            var country = _context.country.Where(x => x.alfa_2 == code_alfa)
                .Select(x => new
                {
                    id = x.id,
                    name = x.name,
                    alfa_2 = x.alfa_2,
                    alfa_3 = x.alfa_3,
                    numeri_code = x.numeric_code,
                    link_iso = x.link_iso,
                    date_created = x.date_created
                });
            if (country == null)
            {
                return NotFound();
            }
            return Ok(country);
        }

        //selet * country  db
        [HttpGet("getCountrys")]
        public ActionResult getCountrys()
        {
            try
            {
                var countrys = _context.country.Select(x => new
                {
                    id = x.id,
                    name = x.name,
                    alfa_2 = x.alfa_2,
                    alfa_3 = x.alfa_3,
                    numeri_code = x.numeric_code,
                    link_iso = x.link_iso,
                    date_created = x.date_created
                });
                return Ok(countrys);
            }
            catch (Exception ex)
            {
                Console.WriteLine("an error ocurred" + ex.ToString());
                return BadRequest();
            }
        }

        //to created new country
        [HttpPost("newCountry")]
        public async Task<ActionResult<CountryModel>> newCountry(CountryModel countryModel)
        {
            try
            {
                countryModel.date_created = DateTime.Now;
                _context.country.Add(countryModel);
                await _context.SaveChangesAsync();
                return CreatedAtAction("GetModelCountry", new { id = countryModel.id }, countryModel);
            }
            catch (Exception ex)
            {
                Console.WriteLine("an error ocurred" + ex.ToString());
                return BadRequest(ex);
            }
        }


        //to update information the country
        [HttpPut("updateCountry")]
        public async Task<ActionResult<CountryModel>> updateCountry(CountryModel countryModel)
        {
            try
            {
                var country = _context.country.FirstOrDefault(x => x.id == countryModel.id);
                country.name = countryModel.name;
                country.alfa_2 = countryModel.alfa_2;
                country.alfa_3 = countryModel.alfa_3;
                country.numeric_code = countryModel.numeric_code;
                country.link_iso = countryModel.link_iso;
                await _context.SaveChangesAsync();
                return CreatedAtAction("GetModelCountry", new { id = countryModel.id }, countryModel);
            }
            catch (Exception ex)
            {
                Console.WriteLine("an error ocurred" + ex.ToString());
                return BadRequest();
            }
        }

        [HttpDelete("deleteCountry")]
        public async Task<ActionResult> deleteCountry(CountryModel countryModel)
        {
            try
            {
                var country = _context.country.FirstOrDefault(x => x.id == countryModel.id);
                _context.country.Remove(country);
                await _context.SaveChangesAsync();
                return Ok();
            }
            catch (Exception ex)
            {
                Console.WriteLine("an error ocurred" + ex.ToString());
                return BadRequest();
            }
        }

        private bool ModelCuntryExists(int id)
        {
            return _context.country.Any(e => e.id == id);
        }
    }
}