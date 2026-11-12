import html
import json
from pathlib import Path


def render_report(result):
    static = Path(__file__).parent / "static"
    template = (static / "index.html").read_text(encoding="utf-8")
    template = template.replace('<link rel="stylesheet" href="/static/style.css">',
                                '<style>' + (static / "style.css").read_text(encoding="utf-8") + '</style>')
    data = json.dumps(result, ensure_ascii=False).replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")
    script = '<script>window.CASE_DATA=' + data + ';</script><script>' + (static / "app.js").read_text(encoding="utf-8") + '</script>'
    template = template.replace('<script src="/static/app.js"></script>', script)
    return template.replace('Mobile DF | Investigation workspace', 'Mobile DF | ' + html.escape(result["case_id"]))
