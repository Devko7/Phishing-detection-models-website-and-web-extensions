from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path

import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DATA_PATH = PROJECT_ROOT / "url-data" / "data" / "urls.csv"
OUTPUT_DIR = Path(__file__).resolve().parent / "data"
DEFAULT_API_BASE = "http://localhost:8000"
SAMPLE_SIZE = 50 # Used to limit the number of samples taken from the dataset
RANDOM_SEED = 42

# This script samples URLs from the url-data dataset and makes calls to the API to classify them. It requires the API to be running.

@dataclass(frozen=True)
class UrlSample:
    url: str
    original_label: str


# Main writer: David Vasilev
# Reviewer: Shaked Gayer
# Contributor: -
def load_samples(n: int = SAMPLE_SIZE, seed: int = RANDOM_SEED) -> list[UrlSample]:
    df = pd.read_csv(DATA_PATH)
    df = df.dropna(subset=["url", "type"])

    benign_df = df[df["type"] == "benign"]
    phishing_df = df[df["type"].isin(["phishing", "defacement", "malware"])]

    if len(benign_df) < n:
        raise ValueError(f"Not enough benign URLs: need {n}, found {len(benign_df)}")
    if len(phishing_df) < n:
        raise ValueError(f"Not enough phishing URLs: need {n}, found {len(phishing_df)}")

    samples: list[UrlSample] = []
    for chosen in (
        benign_df.sample(n=n, random_state=seed),
        phishing_df.sample(n=n, random_state=seed + 1),
    ):
        for _, row in chosen.iterrows():
            url_type = str(row["type"])
            samples.append(
                UrlSample(
                    url=str(row["url"]).strip(),
                    original_label=url_type,
                )
            )
    return samples


# Main writer: David Vasilev
# Reviewer: Shaked Gayer
# Contributor: -
def api_post(base_url: str, path: str, params: dict[str, str]) -> dict:
    url = f"{base_url.rstrip('/')}{path}"
    payload = json.dumps(params).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=payload,
        method="POST",
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=120) as response:
        return json.loads(response.read().decode("utf-8"))


# Main writer: David Vasilev
# Reviewer: Shaked Gayer
# Contributor: -
def classify_url(base_url: str, sample: UrlSample, method: str) -> str | int | float:
    params = {"url": sample.url}
    if method == "ai":
        data = api_post(base_url, "/predict-url-phishing-with-ai", params)
        return data["prediction"]
    if method == "deterministic":
        data = api_post(base_url, "/predict-url-phishing-with-deterministic", params)
        return data["prediction"]
    raise ValueError(f"Unknown method: {method}")


# Main writer: David Vasilev
# Reviewer: Shaked Gayer
# Contributor: -
def run_experiment(base_url: str = DEFAULT_API_BASE, n: int = SAMPLE_SIZE, seed: int = RANDOM_SEED, delay_seconds: float = 0.0) -> pd.DataFrame:
    samples = load_samples(n=n, seed=seed)
    rows: list[dict] = []

    for i, sample in enumerate(samples):
        for method in ("ai", "deterministic"):
            try:
                prediction = classify_url(base_url, sample, method)
            except urllib.error.HTTPError as exc:
                body = exc.read().decode("utf-8", errors="replace")
                prediction = f"HTTP_ERROR_{exc.code}: {body}"
            except urllib.error.URLError as exc:
                prediction = f"URL_ERROR: {exc.reason}"
            except Exception as exc:
                prediction = f"ERROR: {exc}"

            rows.append(
                {
                    "URL": sample.url,
                    "original_label": sample.original_label,
                    "method": method,
                    "prediction": prediction,
                }
            )

        if delay_seconds > 0 and i < len(samples) - 1:
            time.sleep(delay_seconds)

    return pd.DataFrame(rows)


# Main writer: David Vasilev
# Reviewer: Shaked Gayer
# Contributor: -
def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run URL phishing classification experiment against Website_API."
    )
    parser.add_argument(
        "--api-base",
        default=DEFAULT_API_BASE,
        help=f"API base URL (default: {DEFAULT_API_BASE})",
    )
    parser.add_argument(
        "--sample-size",
        type=int,
        default=SAMPLE_SIZE,
        help=f"Samples per category (default: {SAMPLE_SIZE})",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=RANDOM_SEED,
        help=f"Random seed for sampling (default: {RANDOM_SEED})",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=OUTPUT_DIR / "url_experiments_results.csv",
        help="Output CSV path",
    )
    parser.add_argument(
        "--delay",
        type=float,
        default=0.0,
        help="Seconds to wait between URLs (optional rate limiting)",
    )
    args = parser.parse_args()

    print(f"Loading {args.sample_size} benign and {args.sample_size} phishing URLs from url-data...")
    try:
        df = run_experiment(
            base_url=args.api_base,
            n=args.sample_size,
            seed=args.seed,
            delay_seconds=args.delay,
        )
    except ValueError as exc:
        print(f"Dataset error: {exc}", file=sys.stderr)
        sys.exit(1)

    args.output.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(args.output, index=False, encoding="utf-8")
    print(f"Wrote {len(df)} rows to {args.output}")


if __name__ == "__main__":
    main()
