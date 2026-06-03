import json

from ssl_sentinel.models import CheckResult


def format_text(results: list[CheckResult]) -> str:
    """
    Format a list of certificate check results as plain text.

    Args:
        results (list[CheckResult]): The list of check results.

    Returns:
        str: Plain text representation with separators.
    """
    formated_items = []

    for res in results:
        if res.success:
            date_str = res.expiry_date.strftime("%Y-%m-%d")
            detail = f"[{res.status}]: Expires in {res.days_left} days on {date_str}"
        else:
            detail = (
                f"[ERROR]: error checking certificate for {res.hostname}: {res.error}."
            )

        block = f"--> Checking certificate for {res.hostname}\n{detail}"
        formated_items.append(block)

    if len(formated_items) > 1:
        separator = "\n" + "-" * 60 + "\n"
        return separator.join(formated_items) + "\n" + "-" * 60 + "\n"
    elif len(formated_items) == 1:
        return formated_items[0]
    else:
        return ""


def format_json(results: list[CheckResult]) -> str:
    """
    Format a list of certificate check results as a JSON string.

    Args:
        results (list[CheckResult]): The list of check results.

    Returns:
        str: JSON formatted string.
    """
    json_data = []

    for res in results:
        res_dict = {
            "hostname": res.hostname,
            "success": res.success,
            "status": res.status,
            "days_left": res.days_left,
            "expiry_date": res.expiry_date.strftime("%Y-%m-%d")
            if res.expiry_date
            else None,
            "error": res.error,
        }

        json_data.append(res_dict)

    return json.dumps(json_data, indent=2)


FORMATTERS = {"text": format_text, "json": format_json}
