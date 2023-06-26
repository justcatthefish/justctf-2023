import ast
import typing
from typing import Any


VALID_ARRAY_NAME = "c"


class ValidationVisitor(ast.NodeVisitor):
	def __init__(self, input_name, input_count):
		self._input_count = input_count
		self._input_name = input_name
		self._good = True

	def good(self):
		return self._good

	def generic_visit(self, node: ast.AST) -> Any:
		if not self._good:
			return
		ast.NodeVisitor.generic_visit(self, node)

	def validate(self, node: ast.AST) -> Any:
		if not isinstance(node, ast.Expression):
			self._good = False
		else:
			self.generic_visit(node)

	def visit_Expression(self, node: ast.Expression) -> Any:
		if isinstance(node.body, ast.NamedExpr):
			self._good = False
		elif isinstance(node.body, ast.BinOp):
			self._good = False
		elif isinstance(node.body, ast.Lambda):
			self._good = False
		elif isinstance(node.body, ast.IfExp):
			self._good = False
		elif isinstance(node.body, ast.Dict):
			self._good = False
		elif isinstance(node.body, ast.Set):
			self._good = False
		elif isinstance(node.body, ast.ListComp):
			self._good = False
		elif isinstance(node.body, ast.SetComp):
			self._good = False
		elif isinstance(node.body, ast.DictComp):
			self._good = False
		elif isinstance(node.body, ast.GeneratorExp):
			self._good = False
		elif isinstance(node.body, ast.Await):
			self._good = False
		elif isinstance(node.body, ast.Yield):
			self._good = False
		elif isinstance(node.body, ast.YieldFrom):
			self._good = False
		elif isinstance(node.body, ast.Call):
			self._good = False
		elif isinstance(node.body, ast.FormattedValue):
			self._good = False
		elif isinstance(node.body, ast.JoinedStr):
			self._good = False
		elif isinstance(node.body, ast.Attribute):
			self._good = False
		elif isinstance(node.body, ast.Starred):
			self._good = False
		elif isinstance(node.body, ast.Name):
			self._good = False
		elif isinstance(node.body, ast.List):
			self._good = False
		elif isinstance(node.body, ast.Tuple):
			self._good = False
		elif isinstance(node.body, ast.Slice):
			self._good = False
		else:
			self.generic_visit(node)
	def visit_Constant(self, node: ast.Constant) -> Any:
		if not isinstance(node.value, bool):
			self._good = False

	def visit_UnaryOp(self, node: ast.UnaryOp) -> Any:
		if isinstance(node.op, ast.UAdd):
			self._good = False
		elif isinstance(node.op, ast.USub):
			self._good = False
		else:
			self.generic_visit(node)

	def visit_Compare(self, node: ast.Compare) -> Any:
		if isinstance(node.ops, ast.Lt):
			self._good = False
			return
		if isinstance(node.ops, ast.LtE):
			self._good = False
			return
		if isinstance(node.ops, ast.Gt):
			self._good = False
			return
		if isinstance(node.ops, ast.GtE):
			self._good = False
			return
		if isinstance(node.ops, ast.Is):
			self._good = False
			return
		if isinstance(node.ops, ast.IsNot):
			self._good = False
			return
		if isinstance(node.ops, ast.In):
			self._good = False
			return
		if isinstance(node.ops, ast.NotIn):
			self._good = False
			return

		self.generic_visit(node)

	def visit_Subscript(self, node: ast.Subscript) -> Any:
		if not isinstance(node.slice, ast.Constant):
			self._good = False
			return
		if not isinstance(node.slice.value, int):
			self._good = False
			return
		if node.slice.value < 0:
			self._good = False
			return
		if node.slice.value >= self._input_count:
			self._good = False
			return


		if not isinstance(node.value, ast.Name):
			self._good = False
			return
		if not isinstance(node.value.id, str):
			self._good = False
			return
		if node.value.id != self._input_name:
			self._good = False
			return

def validate(tree, card_count):
	validator = ValidationVisitor(VALID_ARRAY_NAME, card_count)
	validator.validate(tree)
	return validator.good()

def evaluate(c, question):
	ast_tree = compile(question, '<string>', 'eval', flags=ast.PyCF_ONLY_AST)
	if validate(ast_tree, len(c)):
		return eval(question)
	else:
		raise Exception("Invalid/illegal code")