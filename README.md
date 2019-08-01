# Technology
Test Technology

# Step 1 - Configuration for data base  SQLServer 2014
run the script called "dbStructure" in the DB folder.

# Step 2 - open the solution in visual Studio 
- configurate the environment variable called "CONNECTION_STRING" in the proyect "apiDemo"
- configurate the environment variable called "CONNECTION_STRING" in the proyect "Exoguardian"
- verify the value of the "DefaultConnection" attribute in the appSettings.json file of the "Exoguardian" project

# step 3 - Execute Migrations to "Exoguardian" proyect.
     updata-database
  
# Step 4 - Add user for the sso-Oauth proyect.
- run the script called "insert_users" in the DB folder.

# Testing endpoints the country, use Postman.
    Ex: https://localhost:4001/api/Country/getCountrys
    
    - int the tab "Authorization" select Type: Oauth 2.0.
    
    -  Clic in the option "Get New Access Token"
               
        - Grant Type : Implicit
        - CalllBack Url : http://localhost:8080/oidc-callback
        - Auth Url : https://localhost:5001/connect/authorize
        - Clint Id : skyfront
        - Scope : api3
        - Client Authentication : Send Client credentials in body.
        
        - Click in the button : Request Token
              * useName : guillermo.pisqui@gmail.com
              * password : Maruntes45@
              
        - Click in the button "Use Token"

