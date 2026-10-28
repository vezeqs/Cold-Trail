from __future__ import annotations

from urllib.parse import quote_plus

ENGINES = {
    "google": "https://www.google.com/search?q={q}",
    "bing": "https://www.bing.com/search?q={q}",
    "duckduckgo": "https://duckduckgo.com/?q={q}",
    "yandex": "https://yandex.com/search/?text={q}",
    "brave": "https://search.brave.com/search?q={q}",
}

REVERSE_IMAGE = {
    "google_lens": "https://lens.google.com/uploadbyurl?url={q}",
    "yandex_images": "https://yandex.com/images/search?rpt=imageview&url={q}",
    "tineye": "https://tineye.com/search?url={q}",
    "bing_visual": "https://www.bing.com/images/search?view=detailv2&iss=sbi&q=imgurl:{q}",
}


def dork_queries(target: str) -> list[str]:
    handle = target.strip().lstrip("@")
    return [
        f'"{handle}"',
        f'"{handle}" -site:github.com -site:reddit.com',
        f'"{handle}" email OR contact',
        f'"{handle}" "about me"',
        f'site:github.com "{handle}"',
        f'site:reddit.com "{handle}"',
        f'site:medium.com "{handle}"',
        f'site:linkedin.com "{handle}"',
        f'site:t.me "{handle}"',
        f'site:pastebin.com "{handle}"',
        f'"{handle}" filetype:pdf',
        f'"{handle}" filetype:txt',
        f'intitle:"{handle}"',
    ]


def dorks(target: str, engines: list[str] | None = None) -> list[dict[str, str]]:
    engines = engines or ["google", "bing", "duckduckgo", "yandex"]
    rows: list[dict[str, str]] = []
    for query in dork_queries(target):
        for engine in engines:
            template = ENGINES.get(engine)
            if template:
                rows.append(
                    {
                        "engine": engine,
                        "query": query,
                        "url": template.format(q=quote_plus(query)),
                    }
                )
    return rows


def reverse_image_links(image_url: str) -> list[dict[str, str]]:
    return [
        {"engine": engine, "url": template.format(q=quote_plus(image_url))}
        for engine, template in REVERSE_IMAGE.items()
    ]
