use master
go

-- first step
if db_id('demoDB') is not null begin
   print 'db exists'
   alter database demoDB set single_user with rollback immediate
   drop database demoDB;
end
go

--second step creacion de base de datos
create database demoDB;
go

--third step usamos la base de datos
use demoDB;
go


-- define tables
create table clientes (
  id int identity	not null	primary key,
  nombres    varchar(50)	not null,
  apellidos    varchar(50)	not null,
  direccion    varchar(50)	not null,
  fecha_creacion date
)

create table tipoCuentas(
	id int identity not null primary key,
	nombre_cuenta varchar(30) not null
);

create table UserCuentas (
  id int identity	not null	primary key,
  id_usuario int not null,
  id_tipo_cuenta int not null,
  id_cuenta    varchar(50)	not null,
  fecha_creacion date,
  constraint fk_idUsuario foreign key(id_usuario) references clientes(id),
  constraint fk_tipoCuenta foreign key(id_tipo_cuenta) references tipoCuentas(id)
)

