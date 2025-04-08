def generate_input_value(input_element, xss_payload):
    name = input_element.get("name", "")
    input_type = input_element.get("type", "text").lower()

    # Use name hints first
    if "user" in name or "email" in name:
        return "admin@example.com"
    elif "pass" in name:
        return "admin123"
    elif "search" in name:
        return "xss test"

    # Use type hints next
    if input_type in ["email"]:
        return "admin@example.com"
    elif input_type in ["password"]:
        return "admin123"
    elif input_type in ["text", "search", "textarea", "url"]:
        return xss_payload
    elif input_type in ["number"]:
        return "123"
    elif input_type in ["tel"]:
        return "1234567890"
    elif input_type in ["date"]:
        return "2025-01-01"
    elif input_type in ["hidden"]:
        return input_element.get("value", "")
    elif input_type in ["checkbox", "radio"]:
        return input_element.get("value", "on")
    
    # Default fallback
    return xss_payload
