from scanner.models import Finding

# Runtimes AWS no longer supports for new deploys. Keep this list short and update it when needed.
DEPRECATED = {
    "python3.6", "python3.7", "python3.8", "python3.9",
    "nodejs12.x", "nodejs14.x", "nodejs16.x", "nodejs18.x",
    "java8", "dotnetcore3.1", "ruby2.7",
}


def deprecated_runtime(session):
    """A function on an unsupported runtime stops getting security patches."""
    fn = session.client("lambda")
    out = []
    for page in fn.get_paginator("list_functions").paginate():
        for f in page["Functions"]:
            if f.get("Runtime") in DEPRECATED:
                out.append(Finding(
                    "LAMBDA-OLD-RUNTIME", "medium", f["FunctionName"],
                    f"Function uses the deprecated runtime {f['Runtime']}.",
                    "Move the function to a current runtime."))
    return out
