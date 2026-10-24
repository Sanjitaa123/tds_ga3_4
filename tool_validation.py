"""JSON Schema validation for catalog-defined tools."""
from jsonschema import Draft202012Validator, validators


def validate_tool_arguments(tool, arguments):
    if not isinstance(tool, dict):
        raise ValueError("Tool definition must be an object")
    if not isinstance(arguments, dict):
        raise ValueError("Tool arguments must be an object")
    schema = tool.get("inputSchema")
    if not isinstance(schema, dict):
        raise ValueError(f"Tool {tool.get('name', '<unknown>')} has no inputSchema")
    validator = Draft202012Validator(schema)
    errors = sorted(validator.iter_errors(arguments), key=lambda e: list(e.path))
    if errors:
        details = "; ".join(error.message for error in errors[:3])
        raise ValueError(f"Invalid arguments for {tool.get('name', 'tool')}: {details}")
    return True


def is_destructive(tool_name, policy):
    return tool_name in set(policy.get("approvalRequiredFor", [])) or tool_name in {"rollback_deployment", "disable_feature"}


def validate_diagnostic_tool(tool, arguments, effect_names):
    if tool.get("name") in set(effect_names):
        raise ValueError("Effect tools cannot be used as diagnostics")
    return validate_tool_arguments(tool, arguments)


def validate_effect_tool(tool, arguments, effect_names):
    if tool.get("name") not in set(effect_names):
        raise ValueError("Tool is not permitted as an effect")
    return validate_tool_arguments(tool, arguments)
