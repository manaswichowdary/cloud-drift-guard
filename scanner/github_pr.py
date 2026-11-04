"""Open a pull request that adds fix files. Uses the plain GitHub REST API so there is nothing to install."""
import base64
import requests

API = "https://api.github.com"


def open_fix_pr(token, repo, base, branch, files, title, body, http=requests):
    h = {"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"}

    def call(method, path, **kw):
        r = http.request(method, f"{API}/repos/{repo}{path}", headers=h, timeout=20, **kw)
        r.raise_for_status()
        return r.json()

    sha = call("GET", f"/git/ref/heads/{base}")["object"]["sha"]
    call("POST", "/git/refs", json={"ref": f"refs/heads/{branch}", "sha": sha})
    for path, text in files.items():
        call("PUT", f"/contents/{path}", json={
            "message": f"Add fix: {path}", "branch": branch,
            "content": base64.b64encode(text.encode()).decode()})
    pr = call("POST", "/pulls", json={"title": title, "head": branch, "base": base, "body": body})
    return pr["html_url"]
