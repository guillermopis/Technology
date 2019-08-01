use master
go

-- first step
if db_id('demoCountrysDB') is not null begin
   print 'db exists'
   alter database demoCountrysDB set single_user with rollback immediate
   drop database demoCountrysDB;
end
go

--second step creacion de base de datos
create database demoCountrysDB;
go

--third step usamos la base de datos
use demoCountrysDB;
go


-- define tables
create table country (
  id int identity	not null	primary key,
  name    varchar(50)	not null,
  alfa_2    varchar(10)	not null,
  alfa_3    varchar(10)	not null,
  numeric_code    varchar(50)	not null,
  link_iso varchar(20) not null,
  date_created date
)

create table CountryDepartaments(
	id int identity not null primary key,
	id_country int not null,
	name varchar(50) not null,
	code varchar (10) not null,
	date_created date,
	constraint fk_idCountry foreign key(id_country) references country(id),
);



