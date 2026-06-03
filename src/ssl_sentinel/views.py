from ssl_sentinel.models import CheckResult


def format_text(results: list[CheckResult]) -> str:

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
