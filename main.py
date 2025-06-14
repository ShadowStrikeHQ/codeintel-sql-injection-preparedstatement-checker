import argparse
import ast
import logging
import os
import sqlite3  # For demonstrating SQL usage

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.
    """
    parser = argparse.ArgumentParser(
        description="Identifies potential SQL injection vulnerabilities by checking for string concatenation in SQL queries."
    )
    parser.add_argument(
        "filepath",
        help="Path to the Python file to analyze.",
    )
    parser.add_argument(
        "--ignore",
        nargs="*",
        help="List of functions/methods to ignore during analysis (e.g., 'my_function').",
        default=[]
    )
    parser.add_argument(
        "--log-level",
        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
        default='INFO',
        help="Set the logging level (default: INFO)"
    )
    return parser


def check_for_sql_injection(filepath, ignore_list=None):
    """
    Analyzes a Python file for potential SQL injection vulnerabilities by detecting string concatenation in SQL query construction.

    Args:
        filepath (str): The path to the Python file to analyze.
        ignore_list (list, optional): A list of function/method names to ignore. Defaults to None.

    Returns:
        list: A list of tuples, where each tuple contains the line number and the potentially vulnerable code snippet.  Returns an empty list if no vulnerabilities are found or if an error occurs.
    """

    if not os.path.exists(filepath):
        logging.error(f"File not found: {filepath}")
        return []

    vulnerable_lines = []
    try:
        with open(filepath, "r") as f:
            code = f.read()
        tree = ast.parse(code)

        for node in ast.walk(tree):
            if isinstance(node, (ast.Call, ast.Expr)):
                # Check for function calls or expressions
                try:
                    if isinstance(node, ast.Call):
                        func_name = get_function_name(node.func)
                        if func_name in ignore_list:
                            continue
                        args = node.args
                    else:
                        args = [node.value]
                    for arg in args:
                        if isinstance(arg, ast.BinOp) and isinstance(arg.op, ast.Add):
                            # String concatenation detected
                            left = ast.unparse(arg.left)
                            right = ast.unparse(arg.right)

                            # Basic check to see if SQL is likely involved (crude but effective)
                            if "SELECT" in left.upper() or "INSERT" in left.upper() or "UPDATE" in left.upper() or "DELETE" in left.upper() or \
                               "SELECT" in right.upper() or "INSERT" in right.upper() or "UPDATE" in right.upper() or "DELETE" in right.upper():
                                vulnerable_lines.append((node.lineno, f"Potential SQL injection vulnerability: {ast.unparse(arg)}"))
                except Exception as e:
                    logging.debug(f"Error processing node: {node} - {e}") # Increased verbosity, making the exceptions DEBUG log level


    except FileNotFoundError:
        logging.error(f"File not found: {filepath}")
        return []
    except Exception as e:
        logging.error(f"Error parsing file: {filepath} - {e}")
        return []

    return vulnerable_lines


def get_function_name(node):
    """
    Extracts the name of a function or method call from an AST node.

    Args:
        node (ast.AST): The AST node representing the function or method call.

    Returns:
        str: The name of the function or method, or None if the name cannot be determined.
    """
    if isinstance(node, ast.Name):
        return node.id
    elif isinstance(node, ast.Attribute):
        return node.attr
    elif isinstance(node, ast.Call): # Added to correctly handle nested calls, such as function(another_function())
        return get_function_name(node.func)
    else:
        return None


def main():
    """
    Main function to execute the SQL injection checker.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    # Set log level based on command line argument
    logging.getLogger().setLevel(args.log_level)

    if not args.filepath:
        logging.error("Filepath is required.")
        return

    try:
        vulnerable_lines = check_for_sql_injection(args.filepath, args.ignore)

        if vulnerable_lines:
            print("Potential SQL injection vulnerabilities found:")
            for line_number, code_snippet in vulnerable_lines:
                print(f"Line {line_number}: {code_snippet}")
        else:
            print("No potential SQL injection vulnerabilities found.")

    except Exception as e:
        logging.critical(f"An unexpected error occurred: {e}")


if __name__ == "__main__":
    # Example Usage:
    # 1. Run on a specific file: python your_script_name.py example.py
    # 2. Ignore certain functions: python your_script_name.py example.py --ignore my_safe_function another_safe_function
    # 3. Set log level to debug: python your_script_name.py example.py --log-level DEBUG

    # Example Vulnerable Code (save as example.py for testing)
    # def get_user(username):
    #     query = "SELECT * FROM users WHERE username = '" + username + "'" # Vulnerable!
    #     cursor.execute(query)
    #
    # def get_item(item_id):
    #     query = "SELECT * FROM items WHERE id = " + str(item_id) # Vulnerable!
    #     cursor.execute(query)
    #
    # def safe_query(item_id):
    #     query = "SELECT * FROM items WHERE id = ?"
    #     cursor.execute(query, (item_id,))
    #
    #
    # def another_safe_function():
    #     print("Doing safe things")

    # Example Safe Code (save as safe_example.py for testing)
    # def safe_get_user(username):
    #     query = "SELECT * FROM users WHERE username = ?"
    #     cursor.execute(query, (username,))

    # if you remove a filename to analyze the code will error.
    main()