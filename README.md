# codeintel-SQL-Injection-PreparedStatement-Checker
Identifies locations where string concatenation is used to build SQL queries instead of using prepared statements, highlighting potential SQL injection vulnerabilities. Employs AST parsing to analyze SQL query construction. - Focused on Tools for static code analysis, vulnerability scanning, and code quality assurance

## Install
`git clone https://github.com/ShadowStrikeHQ/codeintel-sql-injection-preparedstatement-checker`

## Usage
`./codeintel-sql-injection-preparedstatement-checker [params]`

## Parameters
- `-h`: Show help message and exit
- `--ignore`: List of functions/methods to ignore during analysis (e.g., 
- `--log-level`: No description provided

## License
Copyright (c) ShadowStrikeHQ
