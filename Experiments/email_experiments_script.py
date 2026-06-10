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
DATA_DIR = PROJECT_ROOT / "email-data" / "data"
OUTPUT_DIR = Path(__file__).resolve().parent / "data"
DEFAULT_API_BASE = "http://localhost:8000"
SAMPLE_SIZE = 50 # Used to limit the number of samples taken from the dataset
RANDOM_SEED = 42

# This script samples emails from the email-data dataset and makes calls to the API to classify them. It requires the API to be running.

# Main writer: David Vasilev
# Reviewer: Shaked Gayer
# Contributor: -
# Handles CSVs where the text column may contain unquoted commas
def robust_read_csv(filename: Path) -> pd.DataFrame:
    try:
        return pd.read_csv(filename)
    except Exception:
        data = []
        with open(filename, "r", encoding="utf-8", errors="ignore") as f:
            f.readline()
            for line in f:
                line = line.strip()
                if not line:
                    continue
                parts = line.rsplit(",", 1)
                if len(parts) == 2:
                    data.append(parts)
                else:
                    data.append([line, None])
        return pd.DataFrame(data, columns=["text", "label"])


# Main writer: David Vasilev
# Reviewer: Shaked Gayer
# Contributor: -
@dataclass(frozen=True)
class EmailSample:
    content: str
    subject: str
    body: str
    original_label: str
    source_type: str


# Main writer: David Vasilev
# Reviewer: Shaked Gayer
# Contributor: -
def _sample_human(path: Path, label: str, n: int, rng: int) -> list[EmailSample]:
    df = pd.read_csv(path)
    df = df.dropna(subset=["subject", "body"])
    if len(df) < n:
        raise ValueError(f"Not enough rows in {path}: need {n}, found {len(df)}")
    chosen = df.sample(n=n, random_state=rng)
    samples = []
    for _, row in chosen.iterrows():
        subject = str(row["subject"]) if pd.notna(row["subject"]) else ""
        body = str(row["body"]) if pd.notna(row["body"]) else ""
        content = f"{subject} {body}".strip()
        samples.append(
            EmailSample(
                content=content,
                subject=subject,
                body=body,
                original_label=label,
                source_type="Human-written",
            )
        )
    return samples


# Main writer: David Vasilev
# Reviewer: Shaked Gayer
# Contributor: -
def _sample_llm(path: Path, label: str, n: int, rng: int) -> list[EmailSample]:
    df = robust_read_csv(path)
    df = df.dropna(subset=["text"])
    if len(df) < n:
        raise ValueError(f"Not enough rows in {path}: need {n}, found {len(df)}")
    chosen = df.sample(n=n, random_state=rng)
    samples = []
    for _, row in chosen.iterrows():
        text = str(row["text"]).strip()
        samples.append(
            EmailSample(
                content=text,
                subject="",
                body=text,
                original_label=label,
                source_type="LLM-written",
            )
        )
    return samples


# Main writer: David Vasilev
# Reviewer: Shaked Gayer
# Contributor: -
def load_samples(n: int = SAMPLE_SIZE, seed: int = RANDOM_SEED) -> list[EmailSample]:
    rng = seed
    human_dir = DATA_DIR / "human-generated"
    llm_dir = DATA_DIR / "llm-generated"
    return [
        *_sample_human(human_dir / "legit.csv", "legit", n, rng),
        *_sample_human(human_dir / "phishing.csv", "phishing", n, rng + 1),
        *_sample_llm(llm_dir / "legit.csv", "legit", n, rng + 2),
        *_sample_llm(llm_dir / "phishing.csv", "phishing", n, rng + 3),
    ]


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
    with urllib.request.urlopen(req, timeout=60) as response:
        return json.loads(response.read().decode("utf-8"))


# Main writer: David Vasilev
# Reviewer: Shaked Gayer
# Contributor: -
def classify_sample(base_url: str, sample: EmailSample, method: str) -> str | int | float:
    params = {"subject": sample.subject, "body": sample.body}
    if method == "ai":
        path = (
            "/predict-email-phishing-with-ai-llm"
            if sample.source_type == "LLM-written"
            else "/predict-email-phishing-with-ai-human"
        )
        data = api_post(base_url, path, params)
        return data["prediction"]
    if method == "deterministic":
        data = api_post(base_url, "/predict-email-phishing-with-deterministic", params)
        return data["prediction"]
    raise ValueError(f"Unknown method: {method}")


# Main writer: David Vasilev
# Reviewer: Shaked Gayer
# Contributor: -
def detect_llm_sample(base_url: str, sample: EmailSample) -> str | int | float:
    data = api_post(base_url, "/detect-llm-email", {"body": sample.content})
    return data["label"]


# Main writer: David Vasilev
# Reviewer: Shaked Gayer
# Contributor: -
def run_experiment(base_url: str = DEFAULT_API_BASE, n: int = SAMPLE_SIZE, seed: int = RANDOM_SEED, delay_seconds: float = 0.0) -> pd.DataFrame:
    samples = load_samples(n=n, seed=seed)
    rows: list[dict] = []

    for i, sample in enumerate(samples):
        try:
            llm_detection = detect_llm_sample(base_url, sample)
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")
            llm_detection = f"HTTP_ERROR_{exc.code}: {body}"
        except urllib.error.URLError as exc:
            llm_detection = f"URL_ERROR: {exc.reason}"
        except Exception as exc:
            llm_detection = f"ERROR: {exc}"

        for method in ("ai", "deterministic"):
            try:
                prediction = classify_sample(base_url, sample, method)
            except urllib.error.HTTPError as exc:
                body = exc.read().decode("utf-8", errors="replace")
                prediction = f"HTTP_ERROR_{exc.code}: {body}"
            except urllib.error.URLError as exc:
                prediction = f"URL_ERROR: {exc.reason}"
            except Exception as exc:
                prediction = f"ERROR: {exc}"

            rows.append(
                {
                    "email_content": sample.content,
                    "original_label": sample.original_label,
                    "type": sample.source_type,
                    "method": method,
                    "prediction": prediction,
                    "llm_detection": llm_detection,
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
        description="Run email phishing classification experiment against Website_API."
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
        default=OUTPUT_DIR / "email_experiments_results.csv",
        help="Output CSV path",
    )
    parser.add_argument(
        "--delay",
        type=float,
        default=0.0,
        help="Seconds to wait between emails (optional rate limiting)",
    )
    args = parser.parse_args()

    print(f"Loading {args.sample_size} samples per category from email-data...")
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
