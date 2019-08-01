use demoCountrysDB;
select * from dbo.AspNetUserRoles;
select * from dbo.AspNetRoles;
select * from dbo.AspNetUsers;
select * from dbo.AspNetUserClaims;

--paso 1
insert into dbo.AspNetRoles(Id,Name,NormalizedName,ConcurrencyStamp)values('e1bbad92-d631-4780-a097-9acb889154cf','IdentityManagerAdministrator','IDENTITYMANAGERADMINISTRATOR','c704cdc1-245c-4c25-97aa-dd1c98171d1b');
--insert into dbo.AspNetRoles(Id,Name,NormalizedName,ConcurrencyStamp)values('','','','');
--paso 3
insert into dbo.AspNetUserClaims(UserId,ClaimType,ClaimValue)values('7007c405-062c-4f85-a6bc-d35e8af79e78','role','IdentityManagerAdministrator');

--paso 4
insert into dbo.AspNetUserRoles(UserId,RoleId)values('7007c405-062c-4f85-a6bc-d35e8af79e78','e1bbad92-d631-4780-a097-9acb889154cf');
--paso 2
insert into dbo.AspNetUsers(id,UserName,
							NormalizedUserName, 
							Email, NormalizedEmail,EmailConfirmed, 
							PasswordHash, SecurityStamp, ConcurrencyStamp,PhoneNumberConfirmed,TwoFactorEnabled,LockoutEnabled,AccessFailedCount,nit)
		VALUES('7007c405-062c-4f85-a6bc-d35e8af79e78','guillermo.pisqui@gmail.com',
				'GUILLERMO.PISQUI@GMAIL.COM','guillermo.pisqui@gmail.com','GUILLERMO.PISQUI@GMAIL.COM','true',
				'AQAAAAEAACcQAAAAEB1ie4nhgbl+TrpY2SwFYEHOr19uJDKexowxBRbQLa+zhx5MrfVmOeKqyaoeLAfO1Q==',
				'QSI6WZTK34EBVLVZK4W57XCI4EBX7HFN','da4fe6f9-a53d-4d22-b1a9-deffd1180af1',0,0,1,0,'102430268');