import ast
import re
import logging
from pathlib import Path
from typing import Dict, List, Any

class CodeAnalyzer:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.vulnerabilities = []

    def analyze_python_file(self, file_path: Path) -> List[Dict[str, Any]]:
        """Analyze Python file for security issues"""
        vulnerabilities = []

        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()

            # Parse AST
            tree = ast.parse(content)

            # Run various checks
            vulnerabilities.extend(self._check_dangerous_functions(tree, file_path))
            vulnerabilities.extend(self._check_sql_injection(tree, file_path))
            vulnerabilities.extend(self._check_command_injection(tree, file_path))
            vulnerabilities.extend(self._check_path_traversal(tree, file_path))
            vulnerabilities.extend(self._check_weak_crypto(content, file_path))

        except Exception as e:
            self.logger.error(f"Error analyzing Python file {file_path}: {e}")

        return vulnerabilities

    def analyze_java_file(self, file_path: Path) -> List[Dict[str, Any]]:
        """Analyze Java file for security issues"""
        vulnerabilities = []

        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()

            # Run pattern-based checks
            vulnerabilities.extend(self._check_java_sql_injection(content, file_path))
            vulnerabilities.extend(self._check_java_command_injection(content, file_path))
            vulnerabilities.extend(self._check_java_path_traversal(content, file_path))
            vulnerabilities.extend(self._check_java_weak_crypto(content, file_path))
            vulnerabilities.extend(self._check_java_insecure_random(content, file_path))

        except Exception as e:
            self.logger.error(f"Error analyzing Java file {file_path}: {e}")

        return vulnerabilities

    def _check_dangerous_functions(self, tree: ast.AST, file_path: Path) -> List[Dict[str, Any]]:
        """Check for dangerous function calls in Python"""
        vulnerabilities = []
        dangerous_functions = {
            'eval': 'Code injection vulnerability',
            'exec': 'Code injection vulnerability',
            'compile': 'Code injection vulnerability',
            'pickle.loads': 'Insecure deserialization',
            'yaml.load': 'Insecure YAML deserialization',
            'subprocess.call': 'Command injection risk',
            'os.system': 'Command injection risk'
        }

        class DangerousFunctionVisitor(ast.NodeVisitor):
            def __init__(self):
                self.issues = []

            def visit_Call(self, node):
                if isinstance(node.func, ast.Name):
                    if node.func.id in dangerous_functions:
                        self.issues.append({
                            'type': 'dangerous_function',
                            'severity': 'High',
                            'description': f"{dangerous_functions[node.func.id]} - {node.func.id}() used",
                            'file': str(file_path),
                            'line': node.lineno
                        })
                self.generic_visit(node)

        visitor = DangerousFunctionVisitor()
        visitor.visit(tree)
        return visitor.issues

    def _check_sql_injection(self, tree: ast.AST, file_path: Path) -> List[Dict[str, Any]]:
        """Check for SQL injection in Python"""
        vulnerabilities = []

        class SQLInjectionVisitor(ast.NodeVisitor):
            def __init__(self):
                self.issues = []

            def visit_Call(self, node):
                # Check for cursor.execute with string formatting
                if (isinstance(node.func, ast.Attribute) and
                        node.func.attr == 'execute' and
                        len(node.args) > 0):

                    first_arg = node.args[0]
                    if isinstance(first_arg, ast.BinOp) and isinstance(first_arg.op, ast.Mod):
                        self.issues.append({
                            'type': 'sql_injection',
                            'severity': 'High',
                            'description': 'SQL injection vulnerability - string formatting in query',
                            'file': str(file_path),
                            'line': node.lineno
                        })
                self.generic_visit(node)

        visitor = SQLInjectionVisitor()
        visitor.visit(tree)
        return visitor.issues

    def _check_command_injection(self, tree: ast.AST, file_path: Path) -> List[Dict[str, Any]]:
        """Check for command injection in Python"""
        vulnerabilities = []

        class CommandInjectionVisitor(ast.NodeVisitor):
            def __init__(self):
                self.issues = []

            def visit_Call(self, node):
                dangerous_calls = ['os.system', 'subprocess.call', 'subprocess.Popen']

                if isinstance(node.func, ast.Attribute):
                    full_name = f"{node.func.value.id if isinstance(node.func.value, ast.Name) else ''}.{node.func.attr}"

                    if full_name in dangerous_calls and node.args:
                        # Check if argument is a formatted string
                        arg = node.args[0]
                        if isinstance(arg, ast.BinOp) or isinstance(arg, ast.JoinedStr):
                            self.issues.append({
                                'type': 'command_injection',
                                'severity': 'High',
                                'description': f'Potential command injection in {full_name}',
                                'file': str(file_path),
                                'line': node.lineno
                            })
                self.generic_visit(node)

        visitor = CommandInjectionVisitor()
        visitor.visit(tree)
        return visitor.issues

    def _check_path_traversal(self, tree: ast.AST, file_path: Path) -> List[Dict[str, Any]]:
        """Check for path traversal vulnerabilities"""
        vulnerabilities = []

        class PathTraversalVisitor(ast.NodeVisitor):
            def __init__(self):
                self.issues = []

            def visit_Call(self, node):
                file_operations = ['open', 'os.path.join', 'pathlib.Path']

                func_name = None
                if isinstance(node.func, ast.Name):
                    func_name = node.func.id
                elif isinstance(node.func, ast.Attribute):
                    func_name = node.func.attr

                if func_name in file_operations and node.args:
                    # Check if using user input
                    for arg in node.args:
                        if isinstance(arg, ast.Name):
                            self.issues.append({
                                'type': 'path_traversal',
                                'severity': 'High',
                                'description': f'Potential path traversal in {func_name}',
                                'file': str(file_path),
                                'line': node.lineno
                            })
            self.generic_visit(node)

    visitor = PathTraversalVisitor()
    visitor.visit(tree)
    return visitor.issues

def _check_weak_crypto(self, content: str, file_path: Path) -> List[Dict[str, Any]]:
    """Check for weak cryptography patterns"""
    vulnerabilities = []

    patterns = {
        r'hashlib\.md5\(': ('MD5 hash usage', 'High'),
        r'hashlib\.sha1\(': ('SHA1 hash usage', 'High'),
        r'DES\.new\(': ('DES encryption usage', 'High'),
        r'Random\(\)': ('Insecure random number generator', 'Medium'),
        r'ECB\s*\)': ('ECB mode encryption', 'High')
    }

    for pattern, (description, severity) in patterns.items():
        matches = re.finditer(pattern, content)
        for match in matches:
            line_number = content[:match.start()].count('\n') + 1
            vulnerabilities.append({
                'type': 'weak_crypto',
                'severity': severity,
                'description': description,
                'file': str(file_path),
                'line': line_number
            })

    return vulnerabilities

def _check_java_sql_injection(self, content: str, file_path: Path) -> List[Dict[str, Any]]:
    """Check for SQL injection in Java code"""
    vulnerabilities = []

    patterns = [
        r'Statement\.execute\w*\s*\([^;]+\+',
        r'createStatement\s*\(\s*\)\.execute\w*\s*\([^;]+\+',
        r'rawQuery\s*\([^,]+\+',
        r'execSQL\s*\([^;]+\+'
    ]

    for pattern in patterns:
        matches = re.finditer(pattern, content)
        for match in matches:
            line_number = content[:match.start()].count('\n') + 1
            vulnerabilities.append({
                'type': 'sql_injection',
                'severity': 'High',
                'description': 'SQL injection vulnerability - string concatenation in query',
                'file': str(file_path),
                'line': line_number
            })

    return vulnerabilities

def _check_java_command_injection(self, content: str, file_path: Path) -> List[Dict[str, Any]]:
    """Check for command injection in Java code"""
    vulnerabilities = []

    patterns = [
        r'Runtime\.getRuntime\(\)\.exec\s*\([^;]+\+',
        r'ProcessBuilder\s*\([^;]+\+',
        r'Process\s+\w+\s*=\s*[^;]+\+[^;]+\.exec\('
    ]

    for pattern in patterns:
        matches = re.finditer(pattern, content)
        for match in matches:
            line_number = content[:match.start()].count('\n') + 1
            vulnerabilities.append({
                'type': 'command_injection',
                'severity': 'High',
                'description': 'Command injection vulnerability - string concatenation in command',
                'file': str(file_path),
                'line': line_number
            })

    return vulnerabilities

def _check_java_path_traversal(self, content: str, file_path: Path) -> List[Dict[str, Any]]:
    """Check for path traversal in Java code"""
    vulnerabilities = []

    patterns = [
        r'new\s+File\s*\([^)]*\+[^)]*\)',
        r'Paths\.get\s*\([^)]*\+[^)]*\)',
        r'FileInputStream\s*\([^)]*\+[^)]*\)',
        r'FileOutputStream\s*\([^)]*\+[^)]*\)'
    ]

    for pattern in patterns:
        matches = re.finditer(pattern, content)
        for match in matches:
            line_number = content[:match.start()].count('\n') + 1
            vulnerabilities.append({
                'type': 'path_traversal',
                'severity': 'High',
                'description': 'Path traversal vulnerability - unsanitized file path',
                'file': str(file_path),
                'line': line_number
            })

    return vulnerabilities

def _check_java_weak_crypto(self, content: str, file_path: Path) -> List[Dict[str, Any]]:
    """Check for weak cryptography in Java code"""
    vulnerabilities = []

    patterns = {
        r'MessageDigest\.getInstance\s*\(\s*"MD5"\s*\)': ('MD5 hash usage', 'High'),
        r'MessageDigest\.getInstance\s*\(\s*"SHA-?1"\s*\)': ('SHA1 hash usage', 'High'),
        r'Cipher\.getInstance\s*\(\s*"DES[^"]*"\s*\)': ('DES encryption usage', 'High'),
        r'Cipher\.getInstance\s*\(\s*"[^"]*ECB[^"]*"\s*\)': ('ECB mode encryption', 'High'),
        r'SecureRandom\s*\(\s*\)': ('SecureRandom without seed', 'Medium')
    }

    for pattern, (description, severity) in patterns.items():
        matches = re.finditer(pattern, content)
        for match in matches:
            line_number = content[:match.start()].count('\n') + 1
            vulnerabilities.append({
                'type': 'weak_crypto',
                'severity': severity,
                'description': description,
                'file': str(file_path),
                'line': line_number
            })

    return vulnerabilities

def _check_java_insecure_random(self, content: str, file_path: Path) -> List[Dict[str, Any]]:
    """Check for insecure random number generation"""
    vulnerabilities = []

    pattern = r'new\s+Random\s*\(\s*\)'
    matches = re.finditer(pattern, content)

    for match in matches:
        line_number = content[:match.start()].count('\n') + 1
        vulnerabilities.append({
            'type': 'insecure_random',
            'severity': 'Medium',
            'description': 'Insecure random number generator - use SecureRandom instead',
            'file': str(file_path),
            'line': line_number
        })

    return vulnerabilities